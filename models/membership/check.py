#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
"""Run the membership model checks (R-VER-2, R-VER-3).

Modes:
  simulate  The CI run: `safety` must hold on every checked instance, every
            probe must violate `safety`, every witness must be violated (the
            behaviour it names is reachable), and the fixed scenarios in
            scenarios.qnt must pass. Seeds are fixed, so a run is
            reproducible.
  apalache  Bounded model checking of `safety` with Apalache.
  tlc       Exhaustive state exploration of `safety` with TLC.
  inductive Proof of `safety` for all reachable states with Apalache, from the
            inductive invariant in inductive.qnt: init implies IndInv, IndInv
            and one step imply IndInv, and IndInv implies safety; also the
            facts listed under "inductive.implied" in checks.json, and their
            probes, which must fail.

Exit status 0 means every expectation was met. Each run prints the model hash that
the results table in README.md records.
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
# The Apalache version is pinned with the other tools in tools/versions/versions.toml.
with open(HERE.parents[1] / "tools" / "versions" / "versions.toml", "rb") as _f:
    APALACHE = tomllib.load(_f)["apalache"]["version"]



def model_hash():
    """Short SHA-256 of the model sources. A squash merge changes commit hashes,
    so the results table identifies the checked model by this hash."""
    h = hashlib.sha256()
    for name in ("membership.qnt", "instances.qnt"):
        h.update((HERE / name).read_bytes())
    return h.hexdigest()[:12]


CHECKED = ["small", "tiny"]
PROBES = [
    "ignore_bitmap",
    "keep_bit",
    "accept_old_gen",
    "accept_lower",
    "no_halt",
    "halted_accepts",
    "rc_no_forever",
    "proof_needs_cp",
    "reboot_rollback",
    "grant_no_right",
    "no_prune",
    "accept_no_publish",
    "below_window_valid",
    "window_past_set_bit",
    "unbounded_window",
    "need_next",
]
# Probes that random simulation rarely reaches are checked by a fixed scenario
# in SCENARIOS instead: accept_old_data_gen, halted_silent.
WITNESSES = [
    "witnessHalt",
    "witnessForever",
    "witnessAccept",
    "witnessGrant",
    "witnessRootChange",
    "witnessRevokedSends",
    "witnessWindowMoves",
]
SEED = "0x5eed"
# Fixed scenarios in scenarios.qnt, one module each; every test must pass.
SCENARIOS = [
    "scenarios",
    "scenarios_probe_accept_old_data_gen",
    "scenarios_probe_halted_silent",
    "scenarios_convergence",
    "scenarios_probe_need_next",
    "scenarios_window",
    "scenarios_probe_below_window_valid",
]


def quint(args, timeout):
    """Run quint in the model directory; return (status, combined output, seconds)."""
    start = time.monotonic()
    proc = subprocess.run(
        # On Windows npm installs quint.cmd, which subprocess finds only by its full path.
        [shutil.which("quint") or "quint", *args],
        cwd=HERE,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr, time.monotonic() - start


def verdict(output):
    if re.search(r"^\[ok\]", output, re.M):
        return "holds"
    if re.search(r"^\[violation\]", output, re.M):
        return "violated"
    return "error"


def simulate(steps, samples, timeout):
    runs = [(m, "safety", "holds") for m in CHECKED]
    runs += [("probe_" + p, "safety", "violated") for p in PROBES]
    runs += [("small", w, "violated") for w in WITNESSES]
    failures = 0
    for main, inv, expected in runs:
        _, out, secs = quint(
            [
                "run",
                f"--main={main}",
                f"--invariant={inv}",
                f"--max-steps={steps}",
                f"--max-samples={samples}",
                f"--seed={SEED}",
                "--backend=rust",
                SPEC,
            ],
            timeout,
        )
        got = verdict(out)
        ok = got == expected
        failures += not ok
        print(f"{'pass' if ok else 'FAIL'}  {main:24} {inv:20} {got:9} {secs:7.1f} s")
        if got == "error":
            print(out, file=sys.stderr)
    for main in SCENARIOS:
        status, out, secs = quint(["test", f"--main={main}", f"--seed={SEED}", "scenarios.qnt"], timeout)
        ok = status == 0 and "failing" not in out
        failures += not ok
        print(f"{'pass' if ok else 'FAIL'}  {main:45} {'tests pass' if ok else 'tests fail':9} {secs:7.1f} s")
        if not ok:
            print(out, file=sys.stderr)
    return failures


def bounded(backend, main, invariant, temporal, expect, steps, timeout):
    prop = f"--temporal={temporal}" if temporal else f"--invariant={invariant}"
    args = ["verify", f"--main={main}", prop, SPEC]
    if backend == "tlc":
        args.insert(1, "--backend=tlc")
    else:
        args[1:1] = [f"--max-steps={steps}", f"--apalache-version={APALACHE}"]
    _, out, secs = quint(args, timeout)
    print(out)
    got = verdict(out)
    print(f"{backend}  {main}  {temporal or invariant}  {got}  {secs:.0f} s")
    return got != expect


def inductive(main, timeout):
    """The three obligations of the inductive invariant (R-VER-3)."""
    spec = json.loads((HERE / "checks.json").read_text())["inductive"]
    checks = [
        (main, "init implies IndInv", "modelInit", "IndInv", 0, "holds"),
        (main, "IndInv and step imply IndInv", "indInit", "IndInv", 1, "holds"),
        (main, "IndInv implies safety", "indInit", "modelSafety", 0, "holds"),
    ]
    # Further facts that IndInv implies, and their probes, which must fail.
    checks += [(main, f"IndInv implies {n}", "indInit", n, 0, "holds") for n in spec.get("implied", [])]
    checks += [(p["instance"], f"IndInv implies {p['invariant']}", "indInit", p["invariant"], 0, "violated")
               for p in spec.get("impliedProbes", [])]
    failures = 0
    for inst, name, init, inv, steps, expect in checks:
        _, out, secs = quint(
            [
                "verify",
                f"--main={inst}",
                f"--init={init}",
                "--step=modelStep",
                f"--invariant={inv}",
                f"--max-steps={steps}",
                f"--apalache-version={APALACHE}",
                "inductive.qnt",
            ],
            timeout,
        )
        got = verdict(out)
        ok = got == expect
        failures += not ok
        print(f"{'pass' if ok else 'FAIL'}  {inst:24} {name:30} {got:9} {secs:7.0f} s")
        if not ok:
            print(out, file=sys.stderr)
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["simulate", "apalache", "tlc", "inductive"])
    ap.add_argument("--steps", type=int, default=None, help="trace length (simulate: 40, apalache: 5)")
    ap.add_argument("--samples", type=int, default=100000, help="traces per simulator run")
    ap.add_argument("--main", default=None,
                    help="instance for apalache and tlc (default tiny_tlc, e.g. probe_no_halt) "
                         "or for inductive (default tiny_ind, or small_ind)")
    ap.add_argument("--invariant", default="safety", help="invariant for apalache and tlc, e.g. safety or witnessHalt")
    ap.add_argument("--temporal", default=None,
                    help="temporal property instead of an invariant, e.g. haltPropagates (tlc)")
    ap.add_argument("--expect", choices=["holds", "violated"], default="holds",
                    help="expected outcome for apalache and tlc (violated for a probe or a witness)")
    ap.add_argument("--timeout", type=int, default=None, help="seconds per run")
    a = ap.parse_args()
    print(f"model {model_hash()}")
    if a.mode == "inductive":
        # The invariant lives outside the model, so it gets a hash of its own.
        print(f"inductive invariant {hashlib.sha256((HERE / 'inductive.qnt').read_bytes()).hexdigest()[:12]}")
    if a.mode == "simulate":
        failures = simulate(a.steps or 40, a.samples, a.timeout or 1800)
    elif a.mode == "inductive":
        failures = inductive(a.main or "tiny_ind", a.timeout)
    else:
        failures = bounded(a.mode, a.main or "tiny_tlc", a.invariant, a.temporal, a.expect, a.steps or 5, a.timeout)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
