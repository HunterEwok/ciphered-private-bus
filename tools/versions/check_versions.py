#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
"""Check the tool versions pinned in versions.toml.

Without arguments: every file listed under `uses` contains the pinned version
(offline, runs on every pull request).

With --latest: also compares each pin with the newest stable release and fails
if a newer one exists (network, runs weekly).
"""

import argparse
import json
import os
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PINS = Path(__file__).resolve().parent / "versions.toml"
STABLE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def load(path=PINS):
    with open(path, "rb") as f:
        return tomllib.load(f)


def parse(version):
    """Return a comparable tuple for a stable X.Y.Z version, or None."""
    m = STABLE.match(version.strip())
    return tuple(int(x) for x in m.groups()) if m else None


def check_uses(pins, root=ROOT):
    errors = []
    for name, pin in pins.items():
        if parse(pin["version"]) is None:
            errors.append(f"{name}: version {pin['version']!r} is not X.Y.Z")
            continue
        for use in pin["uses"]:
            text = use["text"].replace("{version}", pin["version"])
            path = root / use["file"]
            if not path.is_file():
                errors.append(f"{name}: {use['file']} does not exist")
            elif text not in path.read_text(encoding="utf-8"):
                errors.append(f"{name}: {use['file']} does not contain {text!r}")
    return errors


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cpb-version-check"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8")


def latest(source):
    kind, _, ident = source.partition(":")
    if kind == "github":
        return json.loads(fetch(f"https://api.github.com/repos/{ident}/releases/latest"))["tag_name"].lstrip("v")
    if kind == "rubygems":
        return json.loads(fetch(f"https://rubygems.org/api/v1/versions/{ident}/latest.json"))["version"]
    if kind == "rust-stable":
        manifest = tomllib.loads(fetch("https://static.rust-lang.org/dist/channel-rust-stable.toml"))
        return manifest["pkg"]["rust"]["version"].split()[0]
    raise ValueError(f"unknown source {source!r}")


def check_latest(pins):
    errors = []
    for name, pin in pins.items():
        try:
            newest = latest(pin["latest"])
        except (OSError, ValueError, KeyError) as e:
            errors.append(f"{name}: cannot read the newest release from {pin['latest']}: {e}")
            continue
        if parse(newest) is None:
            errors.append(f"{name}: newest release {newest!r} is not X.Y.Z")
        elif parse(newest) > parse(pin["version"]):
            errors.append(f"{name}: pinned {pin['version']}, newest is {newest}")
        else:
            print(f"{name}: {pin['version']} is current")
    return errors


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--latest", action="store_true", help="also compare with the newest releases")
    args = ap.parse_args()
    pins = load()
    errors = check_uses(pins)
    if args.latest:
        errors += check_latest(pins)
    for e in errors:
        print(e, file=sys.stderr)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
