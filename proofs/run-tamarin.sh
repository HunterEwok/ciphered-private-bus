#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
#
# Proves the lemmas of a Tamarin model (a folder under proofs/, named by -m)
# on a shared Linux machine, with progress output and a summary. Each lemma is
# a separate prover process, so lemmas run in parallel; together they take at
# most -s (default 0.85) of the cores and memory. With -p the probes listed in
# the model's checks.json run too: each probe is a deliberate defect selected
# with -D, and its lemma must be falsified (R-VER-2). With -c only the quick
# subset listed under "ci" in checks.json runs, as in CI.
#
# Tamarin and Maude are downloaded into the work folder on first use, at the
# versions pinned in tools/versions/versions.toml.
#
# Usage:
#   proofs/run-tamarin.sh -m pairing -w ~/cpb-runs [-p] [-c] [-s 0.85] [-t HOURS]
#
# Exit status: 0 every outcome as expected, 1 otherwise.

set -euo pipefail

TAMARIN_VERSION="1.12.0"
MAUDE_VERSION="3.5.1"

MODEL=""; WORK=""; PROBES=0; CI=0; SHARE="0.85"; HOURS=0; INTERVAL=60
USAGE="usage: $0 -m MODEL -w WORKDIR [-p] [-c] [-s SHARE] [-t HOURS]"
while getopts "m:w:pcs:t:" opt; do
  case "$opt" in
    m) MODEL="$OPTARG" ;;
    w) WORK="$OPTARG" ;;
    p) PROBES=1 ;;
    c) CI=1; PROBES=1 ;;
    s) SHARE="$OPTARG" ;;
    t) HOURS="$OPTARG" ;;
    *) echo "$USAGE" >&2; exit 2 ;;
  esac
done
[ -n "$MODEL" ] && [ -n "$WORK" ] || { echo "$USAGE" >&2; exit 2; }

say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

PROOFS="$(cd "$(dirname "$0")" && pwd)"
DIR="$PROOFS/$MODEL"
SPTHY="$DIR/$MODEL.spthy"
CHECKS="$DIR/checks.json"
[ -f "$SPTHY" ] && [ -f "$CHECKS" ] || { echo "no model $MODEL ($SPTHY, $CHECKS)" >&2; exit 2; }
mkdir -p "$WORK"; WORK="$(cd "$WORK" && pwd)"

# Tools.
TOOLS="$WORK/tools-tamarin-$TAMARIN_VERSION-maude-$MAUDE_VERSION"
if [ ! -x "$TOOLS/tamarin-prover" ] || [ ! -x "$TOOLS/maude" ]; then
  say "Downloading Tamarin $TAMARIN_VERSION and Maude $MAUDE_VERSION into $TOOLS"
  mkdir -p "$TOOLS"
  curl -fsSL -o "$TOOLS/tamarin.tgz" \
    "https://github.com/tamarin-prover/tamarin-prover/releases/download/$TAMARIN_VERSION/tamarin-prover-$TAMARIN_VERSION-linux64-ubuntu.tar.gz"
  tar -xzf "$TOOLS/tamarin.tgz" -C "$TOOLS"
  curl -fsSL -o "$TOOLS/maude.zip" \
    "https://github.com/maude-lang/Maude/releases/download/Maude$MAUDE_VERSION/Maude-$MAUDE_VERSION-linux-x86_64.zip"
  (cd "$TOOLS" && python3 -c "import zipfile; zipfile.ZipFile('maude.zip').extractall('.')")
  chmod +x "$TOOLS/tamarin-prover" "$TOOLS/maude"
  rm -f "$TOOLS/tamarin.tgz" "$TOOLS/maude.zip"
fi
export PATH="$TOOLS:$PATH" LANG=C.UTF-8 LC_ALL=C.UTF-8

# Resources: every prover gets 2 cores; jobs and memory follow the share.
CORES=$(nproc)
MEM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
JOBS=$(python3 -c "print(max(1, int($CORES * $SHARE) // 2))")
JOB_GB=$(python3 -c "print(max(2, int($MEM_GB * $SHARE) // $JOBS))")

MODEL_HASH=$(sha256sum "$SPTHY" | cut -c1-12)
COMMIT=$(git -C "$PROOFS" rev-parse --short HEAD 2>/dev/null || echo unknown)
RUN="$WORK/tamarin-$MODEL-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN"
say "Model $MODEL $MODEL_HASH, commit $COMMIT, Tamarin $TAMARIN_VERSION, run folder $RUN"
say "$JOBS provers at a time, 2 cores and $JOB_GB GB each ($CORES cores, $MEM_GB GB RAM)"

# Jobs: "name|define|lemma|expected". The model itself: every lemma verified
# (an exists-trace lemma is verified when its trace is found).
LEMMAS=$(grep -oE '^lemma [A-Za-z0-9_]+' "$SPTHY" | awk '{print $2}')
JOBLIST="$RUN/jobs.txt"
# shellcheck disable=SC2086
python3 - "$CHECKS" "$PROBES" "$CI" $LEMMAS > "$JOBLIST" <<'EOF'
import json, sys
checks, lemmas = json.load(open(sys.argv[1])), sys.argv[4:]
probes, ci = sys.argv[2] == "1", sys.argv[3] == "1"
if ci:
    unknown = [l for l in checks["ci"]["lemmas"] if l not in lemmas]
    if unknown:
        sys.exit(f"checks.json: ci names unknown lemmas {unknown}")
    lemmas = checks["ci"]["lemmas"]
for lemma in lemmas:
    print(f"model|-|{lemma}|verified")
if probes:
    for define, lemma in checks["probes"].items():
        if not ci or define in checks["ci"]["probes"]:
            print(f"{define}|{define}|{lemma}|falsified")
EOF
TOTAL=$(wc -l < "$JOBLIST")

# Every variant (the model and each probe) must parse before any prover starts.
for define in - $(python3 -c 'import json, sys; print(*json.load(open(sys.argv[1]))["probes"])' "$CHECKS"); do
  dflag=(); [ "$define" != "-" ] && dflag=("-D$define")
  if ! tamarin-prover "${dflag[@]}" --derivcheck-timeout=0 "$SPTHY" > "$RUN/parse-$define.log" 2>&1; then
    say "The model does not parse with ${dflag[*]:-no defines}:"; sed 's/^/  /' "$RUN/parse-$define.log" | tail -15
    exit 1
  fi
done
say "The model and every probe parse"
say "$TOTAL lemma checks"

run_one() {
  local name="$1" define="$2" lemma="$3" log="$4"
  local dflag=()
  [ "$define" != "-" ] && dflag=("-D$define")
  local limit=()
  [ "$HOURS" != 0 ] && limit=(timeout "$(python3 -c "print(int($HOURS * 3600))")")
  nice -n 10 "${limit[@]}" tamarin-prover "${dflag[@]}" --prove="$lemma" "$SPTHY" \
    +RTS -N2 -M"${JOB_GB}"G -RTS > "$log" 2>&1 || true
}

verdict() {
  local lemma="$1" log="$2"
  local line
  line=$(grep -E "^  $lemma \((all-traces|exists-trace)\): " "$log" | tail -1 || true)
  case "$line" in
    *": verified"*) echo verified ;;
    *": falsified"*) echo falsified ;;
    *"analysis incomplete"*) echo "no verdict" ;;
    *)
      if grep -q "heap overflow\|out of memory" "$log"; then echo "no verdict: out of memory"
      elif [ ! -s "$log" ]; then echo "no verdict: empty log"
      else echo "no verdict: $(grep -m1 -iE 'error|exception|unexpected' "$log" | cut -c1-120)"; fi ;;
  esac
}

declare -A PIDS=() STARTS=()
i=0; done_n=0; started_all=$(date +%s); last=0
mapfile -t ROWS < "$JOBLIST"
RESULTS="$RUN/results.txt"; : > "$RESULTS"
while [ "$done_n" -lt "$TOTAL" ]; do
  while [ "${#PIDS[@]}" -lt "$JOBS" ] && [ "$i" -lt "$TOTAL" ]; do
    IFS='|' read -r name define lemma expected <<< "${ROWS[$i]}"
    log="$RUN/$(printf '%02d' $((i + 1)))-$name-$lemma.log"
    run_one "$name" "$define" "$lemma" "$log" &
    PIDS[$i]=$!; STARTS[$i]=$(date +%s)
    say "Started $name / $lemma (expected $expected)"
    i=$((i + 1))
  done
  sleep 2
  for k in "${!PIDS[@]}"; do
    if ! kill -0 "${PIDS[$k]}" 2>/dev/null; then
      wait "${PIDS[$k]}" 2>/dev/null || true
      IFS='|' read -r name define lemma expected <<< "${ROWS[$k]}"
      log="$RUN/$(printf '%02d' $((k + 1)))-$name-$lemma.log"
      v=$(verdict "$lemma" "$log")
      mins=$(python3 -c "print(f'{($(date +%s) - ${STARTS[$k]}) / 60:.1f}')")
      ok=FAIL; [ "$v" = "$expected" ] && ok=pass
      say "$name / $lemma: $v ($mins min)"
      printf '%-4s  %-22s %-26s %-10s %8s min  %s\n' "$ok" "$name" "$lemma" "$expected" "$mins" "$v" >> "$RESULTS"
      unset "PIDS[$k]"; done_n=$((done_n + 1))
    fi
  done
  now=$(date +%s)
  if [ $((now - last)) -ge "$INTERVAL" ] && [ "${#PIDS[@]}" -gt 0 ]; then
    last=$now
    running=""
    for k in "${!PIDS[@]}"; do
      IFS='|' read -r name define lemma expected <<< "${ROWS[$k]}"
      running="$running $lemma $(( (now - ${STARTS[$k]}) / 60 ))m,"
    done
    say "$(( (now - started_all) / 60 )) min elapsed | done $done_n of $TOTAL | running:${running%,}"
  fi
done

FAILS=$(grep -c '^FAIL' "$RESULTS" || true)
{
  echo "model: $MODEL"
  echo "model hash: $MODEL_HASH"
  echo "commit: $COMMIT"
  echo "tamarin: $TAMARIN_VERSION, maude: $MAUDE_VERSION, $JOBS at a time, $JOB_GB GB each"
  echo "started: $(date -u -d "@$started_all" '+%Y-%m-%d %H:%M:%SZ'), ended: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo
  sort -k2,2 -k3,3 "$RESULTS"
  echo
  if [ "$FAILS" = 0 ]; then echo "result: every outcome as expected"; else echo "result: $FAILS outcome(s) not as expected"; fi
} > "$RUN/summary.txt"
say "Summary ($RUN/summary.txt):"
sed 's/^/  /' "$RUN/summary.txt"
[ "$FAILS" = 0 ]
