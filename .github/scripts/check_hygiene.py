#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok

"""Repository hygiene checks: English-only text, no AI traces or chat links,
clean commit authors, and no local paths or leaked secrets."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ALLOWED_EMAILS = {
    "88090358+hunterewok@users.noreply.github.com",
    "noreply@github.com",
    "49699333+dependabot[bot]@users.noreply.github.com",
}

# Allowed non-ASCII characters (standard typographic punctuation and math/symbols).
ALLOWED_NON_ASCII = set(
    "—–‘’“”•…·§©®™°±×÷≠≤≥→←↔⇒⇔"
)

# Forbidden scripts (Cyrillic, CJK, Arabic, Hebrew, etc.).
FORBIDDEN_SCRIPT_RE = re.compile(
    r"[\u0400-\u04FF"  # Cyrillic
    r"\u0500-\u052F"   # Cyrillic Supplement
    r"\u0590-\u05FF"   # Hebrew
    r"\u0600-\u06FF"   # Arabic
    r"\u3040-\u30FF"   # Hiragana / Katakana
    r"\u4E00-\u9FFF"   # CJK Unified Ideographs
    r"\uAC00-\uD7AF]"  # Hangul
)

AI_TRACE_PATTERNS = [
    (re.compile(r"(?i)\bgenerated\s+(?:by|with)\s+(?:ai|gemini|claude|chatgpt|gpt|copilot|cursor|antigravity|llm)\b"), "AI generation notice"),
    (re.compile(r"(?i)\b(?:made|written|created)\s+(?:by|with)\s+(?:ai|gemini|claude|chatgpt|copilot|antigravity)\b"), "AI attribution notice"),
    (re.compile(r"(?i)claude\.ai/(?:[^\s)\]>`\"']+)"), "Claude conversation link"),
    (re.compile(r"(?i)chatgpt\.com/(?:[^\s)\]>`\"']+)"), "ChatGPT conversation link"),
    (re.compile(r"(?i)chat\.openai\.com/(?:[^\s)\]>`\"']+)"), "OpenAI chat link"),
    (re.compile(r"(?i)gemini\.google\.com/(?:[^\s)\]>`\"']+)"), "Gemini conversation link"),
    (re.compile(r"(?i)aistudio\.google\.com/(?:[^\s)\]>`\"']+)"), "AI Studio link"),
    (re.compile(r"(?i)conversation://"), "Internal conversation URI"),
    (re.compile(r"(?i)^\s*claude-session:", re.MULTILINE), "Claude session trailer"),
    (re.compile(r"(?i)\b(?:claude[ -])?(?:opus|sonnet|haiku)[ -]?\d"), "Claude model identifier"),
    (re.compile(r"(?i)\bgemini[ -]?\d+(?:\.\d+)?[ -]?(?:pro|flash|ultra)\b"), "Gemini model identifier"),
    (re.compile(r"(?i)\bgpt-[45](?:o|turbo)?\b"), "GPT model identifier"),
]

SECRET_AND_PATH_PATTERNS = [
    (re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), "Private key header"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"/home/antigravity\b"), "Local VM path (/home/antigravity)"),
]

CO_AUTHOR_RE = re.compile(r"(?im)^co-authored-by:\s*(.*?)\s*<([^>]*)>\s*$")

# Files that legitimately mention forbidden patterns as part of the hygiene rule itself.
SELF_EXEMPT = {
    ".github/scripts/check_hygiene.py",
}


def check_text(label: str, text: str, errors: list[str], *, check_scripts: bool = True) -> None:
    if check_scripts:
        for idx, line in enumerate(text.splitlines(), 1):
            m = FORBIDDEN_SCRIPT_RE.search(line)
            if m:
                errors.append(f"{label}:{idx}: non-English script character {m.group(0)!r} found")
            for ch in line:
                if ord(ch) > 127 and ch not in ALLOWED_NON_ASCII and not FORBIDDEN_SCRIPT_RE.match(ch):
                    errors.append(f"{label}:{idx}: unexpected non-ASCII character {ch!r} (U+{ord(ch):04X})")
                    break

    for pattern, desc in AI_TRACE_PATTERNS:
        m = pattern.search(text)
        if m:
            errors.append(f"{label}: forbidden {desc}: {m.group(0)!r}")

    for pattern, desc in SECRET_AND_PATH_PATTERNS:
        m = pattern.search(text)
        if m:
            errors.append(f"{label}: forbidden {desc}: {m.group(0)!r}")


def check_tracked_files(errors: list[str]) -> None:
    res = subprocess.run(
        ["git", "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    paths = [p.decode("utf-8", errors="replace") for p in res.stdout.split(b"\0") if p]
    if not paths:
        # Fallback for untracked initial setup before first commit.
        paths = [
            str(p)
            for p in Path(".").rglob("*")
            if p.is_file() and ".git" not in p.parts and "target" not in p.parts
        ]

    for rel in paths:
        norm = rel.lstrip("./")
        if norm in SELF_EXEMPT:
            continue
        p = Path(norm)
        if not p.is_file():
            continue
        raw = p.read_bytes()
        if b"\x00" in raw:
            continue  # Binary file
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{norm}: file is not valid UTF-8")
            continue
        check_text(norm, text, errors)


def check_commits(base: str, head: str, errors: list[str]) -> None:
    sep = "\x1e"
    field_sep = "\x1f"
    fmt = f"%H{field_sep}%ae{field_sep}%ce{field_sep}%B{sep}"
    res = subprocess.run(
        ["git", "log", f"--format={fmt}", f"{base}..{head}"],
        capture_output=True,
        text=True,
        check=True,
    )
    for record in res.stdout.split(sep):
        record = record.strip("\n")
        if not record:
            continue
        parts = record.split(field_sep, 3)
        if len(parts) != 4:
            continue
        sha, author_email, committer_email, msg = parts
        short = sha[:9]
        if author_email.lower() not in ALLOWED_EMAILS:
            errors.append(f"commit {short}: disallowed author email <{author_email}>")
        if committer_email.lower() not in ALLOWED_EMAILS:
            errors.append(f"commit {short}: disallowed committer email <{committer_email}>")
        for m in CO_AUTHOR_RE.findAll(msg) if hasattr(CO_AUTHOR_RE, "findAll") else CO_AUTHOR_RE.findall(msg):
            co_email = m[1].strip().lower()
            if co_email not in ALLOWED_EMAILS:
                errors.append(f"commit {short}: disallowed Co-authored-by <{m[1]}>")
        check_text(f"commit {short}", msg, errors)


def main() -> int:
    errors: list[str] = []
    check_tracked_files(errors)

    base = os.environ.get("BASE_SHA", "").strip()
    head = os.environ.get("HEAD_SHA", "").strip()
    if base and head and base != "0" * 40:
        check_commits(base, head, errors)

    pr_title = os.environ.get("PR_TITLE", "")
    pr_body = os.environ.get("PR_BODY", "")
    if pr_title:
        check_text("PR title", pr_title, errors)
    if pr_body:
        check_text("PR description", pr_body, errors)

    if len(sys.argv) == 3 and sys.argv[1] == "--commit-msg":
        msg = Path(sys.argv[2]).read_text(encoding="utf-8", errors="replace")
        check_text("commit message", msg, errors)

    if errors:
        print("Hygiene check failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Hygiene check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
