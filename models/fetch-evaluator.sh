#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok

# Installs the Rust evaluator that the pinned Quint uses for `quint run` and
# `quint test`. Quint itself would fetch it through the GitHub API without a
# token, which shared CI runners exhaust ("rate limit exceeded"); the GitHub
# CLI here uses the job's token (GH_TOKEN). The version is the one the
# installed Quint asks for, so a Quint update needs no change here.
set -eu
cd "$(dirname "$0")"
version=$(node -p "require('@informalsystems/quint/dist/src/rust/binaryManager.js').QUINT_EVALUATOR_VERSION")
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) asset=quint_evaluator-x86_64-unknown-linux-gnu.tar.gz ;;
  Linux-aarch64) asset=quint_evaluator-aarch64-unknown-linux-gnu.tar.gz ;;
  *) echo "no evaluator asset for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
dir="${QUINT_HOME:-$HOME/.quint}/rust-evaluator-$version"
if [ -x "$dir/quint_evaluator" ]; then
  echo "Rust evaluator $version already installed"
  exit 0
fi
mkdir -p "$dir"
gh release download "evaluator/$version" --repo quint-co/quint --pattern "$asset" --dir "$dir"
tar -xzf "$dir/$asset" -C "$dir"
rm "$dir/$asset"
chmod +x "$dir/quint_evaluator"
echo "Rust evaluator $version installed in $dir"
