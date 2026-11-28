#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
#
# Proves the lemmas of a Tamarin model (a folder under proofs/, named by -m)
# on a shared Linux machine, with progress output and a summary. Each lemma is
# a separate prover process, so lemmas run in parallel; together they take at
# most -s (default 0.85) of the cores and memory. With -p the probes listed in
# the model's checks.json run too: each probe is a deliberate defect selected
# with -D, and its lemma must be falsified (R-VER-2), or, for a lemma named
# *_counterexample, its counterexample trace must be found. With -c only the quick
# subset listed under "ci" in checks.json runs, as in CI. With -o NAME only the
# checks whose name (model or a probe) or lemma is NAME run; fewer provers at
# a time means more memory for each.
#
# Tamarin and Maude are downloaded into the work folder on first use, at the
# versions pinned in tools/versions/versions.toml, and checked against the
# pinned SHA-256 of each archive on every run.
#
# Usage:
#   proofs/run-tamarin.sh -m pairing -w ~/cpb-runs [-p] [-c] [-o NAME] [-s 0.85] [-t HOURS]
#
# Exit status: 0 every outcome as expected, 1 otherwise.

set -euo pipefail

TAMARIN_VERSION="1.12.0"
MAUDE_VERSION="3.5.1"
# SHA-256 of the release archives; change them together with the versions.
TAMARIN_SHA256="201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6"
MAUDE_SHA256="72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c"

MODEL=""; WORK=""; PROBES=0; CI=0; ONLY=""; SHARE="0.85"; HOURS=0; INTERVAL=60
USAGE="usage: $0 -m MODEL -w WORKDIR [-p] [-c] [-o NAME] [-s SHARE] [-t HOURS]"
while getopts "m:w:pco:s:t:" opt; do
  case "$opt" in
    m) MODEL="$OPTARG" ;;
    w) WORK="$OPTARG" ;;
    p) PROBES=1 ;;
    c) CI=1; PROBES=1 ;;
    s) SHARE="$OPTARG" ;;
    t) HOURS="$OPTARG" ;;
    o) ONLY="$OPTARG" ;;
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

# Tools. The archives are kept and checked on every run; the binaries are
# extracted again from a checked archive whenever they are missing.
TOOLS="$WORK/tools-tamarin-$TAMARIN_VERSION-maude-$MAUDE_VERSION"
mkdir -p "$TOOLS"
fetch() {
  local file="$1" url="$2" sum="$3"
  if [ ! -f "$TOOLS/$file" ]; then
    say "Downloading $url"
    curl -fsSL -o "$TOOLS/$file.part" "$url"
    mv "$TOOLS/$file.part" "$TOOLS/$file"
  fi
  if ! echo "$sum  $TOOLS/$file" | sha256sum -c --quiet -; then
    say "SHA-256 of $TOOLS/$file does not match the pinned $sum; delete the file to download it again"
    exit 1
  fi
}
fetch tamarin.tgz \
  "https://github.com/tamarin-prover/tamarin-prover/releases/download/$TAMARIN_VERSION/tamarin-prover-$TAMARIN_VERSION-linux64-ubuntu.tar.gz" \
  "$TAMARIN_SHA256"
fetch maude.zip \
  "https://github.com/maude-lang/Maude/releases/download/Maude$MAUDE_VERSION/Maude-$MAUDE_VERSION-linux-x86_64.zip" \
  "$MAUDE_SHA256"
if [ ! -x "$TOOLS/tamarin-prover" ] || [ ! -x "$TOOLS/maude" ]; then
  tar -xzf "$TOOLS/tamarin.tgz" -C "$TOOLS"
  (cd "$TOOLS" && python3 -c "import zipfile; zipfile.ZipFile('maude.zip').extractall('.')")
  chmod +x "$TOOLS/tamarin-prover" "$TOOLS/maude"
fi
say "Tamarin $TAMARIN_VERSION and Maude $MAUDE_VERSION archives match their pinned SHA-256"
export PATH="$TOOLS:$PATH" LANG=C.UTF-8 LC_ALL=C.UTF-8

# Resources of the machine; they are split once the checks are known.
CORES=$(nproc)
MEM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)

MODEL_HASH=$(sha256sum "$SPTHY" | cut -c1-12)
COMMIT=$(git -C "$PROOFS" rev-parse --short HEAD 2>/dev/null || echo unknown)
RUN="$WORK/tamarin-$MODEL-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN"
say "Model $MODEL $MODEL_HASH, commit $COMMIT, Tamarin $TAMARIN_VERSION, run folder $RUN"

# Jobs: "name|define|lemma|expected". The model itself: every lemma verified
# (an exists-trace lemma is verified when its trace is found). A probe
# falsifies its lemma; a lemma named *_counterexample is an exists-trace
# search for a counterexample to a property, so a probe must find its trace
# (verified), and the model itself does not run it.
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
    unknown = [d for d in checks["ci"]["probes"] if d not in checks["probes"]]
    if unknown:
        sys.exit(f"checks.json: ci names unknown probes {unknown}")
for lemma in lemmas:
    if not lemma.endswith("_counterexample"):
        print(f"model|-|{lemma}|verified")
if probes:
    for define, lemma in checks["probes"].items():
        if not ci or define in checks["ci"]["probes"]:
            expected = "verified" if lemma.endswith("_counterexample") else "falsified"
            print(f"{define}|{define}|{lemma}|{expected}")
EOF
if [ -n "$ONLY" ]; then
  awk -F'|' -v n="$ONLY" '$1 == n || $3 == n' "$JOBLIST" > "$JOBLIST.only"
  mv "$JOBLIST.only" "$JOBLIST"
fi
TOTAL=$(wc -l < "$JOBLIST")
[ "$TOTAL" -gt 0 ] || { say "No check matches -o $ONLY"; exit 2; }
# Every prover gets 2 cores; the number at a time follows the share and the
# number of checks, and the memory is split among them.
JOBS=$(python3 -c "print(max(1, min($TOTAL, int($CORES * $SHARE) // 2)))")
JOB_GB=$(python3 -c "print(max(2, int($MEM_GB * $SHARE) // $JOBS))")
say "$JOBS provers at a time, 2 cores and $JOB_GB GB each ($CORES cores, $MEM_GB GB RAM)"

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
  local status=0
  nice -n 10 "${limit[@]}" tamarin-prover "${dflag[@]}" --prove="$lemma" "$SPTHY" \
    +RTS -N2 -M"${JOB_GB}"G -RTS > "$log" 2>&1 || status=$?
  echo "prover exit status: $status" >> "$log"
}

verdict() {
  local lemma="$1" log="$2"
  local line status
  line=$(grep -E "^  $lemma \((all-traces|exists-trace)\): " "$log" | tail -1 || true)
  status=$(sed -n 's/^prover exit status: //p' "$log" | tail -1)
  # A verdict counts only from a prover that finished normally (R-VER-5).
  [ "$status" = 0 ] || line=""
  case "$line" in
    *": verified"*) echo verified ;;
    *": falsified"*) echo falsified ;;
    *"analysis incomplete"*) echo "no verdict" ;;
    *)
      local cause
      case "$status" in
        124) cause="time limit (-t) reached" ;;
        137) cause="killed (SIGKILL), most likely by the kernel for lack of memory; see dmesg" ;;
        "") cause="no exit status recorded" ;;
        *) cause="exit status $status" ;;
      esac
      if [ "$status" = 251 ] || grep -qiE "heap overflow|heap exhausted|out of memory" "$log"; then cause="out of memory (heap limit ${JOB_GB} GB)"
      elif grep -qiE 'error|exception|unexpected' "$log"; then
        cause="$cause; $(grep -m1 -iE 'error|exception|unexpected' "$log" | cut -c1-120)"
      fi
      echo "no verdict: $cause" ;;
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
