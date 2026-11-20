#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run the membership model checks (R-VER-2, R-VER-3).

Modes:
  simulate  The CI run: `safety` must hold on every checked instance, every
            probe must violate `safety`, and every witness must be violated
            (the behaviour it names is reachable). Seeds are fixed, so a run is
            reproducible.
  apalache  Bounded model checking of `safety` with Apalache.
  tlc       Exhaustive state exploration of `safety` with TLC.

Exit status 0 means every expectation was met.
"""

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = "instances.qnt"

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
]
WITNESSES = [
    "witnessHalt",
    "witnessForever",
    "witnessAccept",
    "witnessGrant",
    "witnessRootChange",
    "witnessRevokedSends",
]
SEED = "0x5eed"


def quint(args, timeout):
    """Run quint in the model directory; return (status, combined output, seconds)."""
    start = time.monotonic()
    proc = subprocess.run(
        ["quint", *args],
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
    return failures


def bounded(backend, main, steps, timeout):
    args = ["verify", f"--main={main}", "--invariant=safety", SPEC]
    if backend == "tlc":
        args.insert(1, "--backend=tlc")
    else:
        args.insert(1, f"--max-steps={steps}")
    _, out, secs = quint(args, timeout)
    print(out)
    got = verdict(out)
    print(f"{backend}  {main}  safety  {got}  {secs:.0f} s")
    return got != "holds"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["simulate", "apalache", "tlc"])
    ap.add_argument("--steps", type=int, default=None, help="trace length (simulate: 40, apalache: 5)")
    ap.add_argument("--samples", type=int, default=100000, help="traces per simulator run")
    ap.add_argument("--main", default="tiny", help="instance for apalache and tlc")
    ap.add_argument("--timeout", type=int, default=None, help="seconds per run")
    a = ap.parse_args()
    if a.mode == "simulate":
        failures = simulate(a.steps or 40, a.samples, a.timeout or 1800)
    else:
        failures = bounded(a.mode, a.main, a.steps or 5, a.timeout)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
