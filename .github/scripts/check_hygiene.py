#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok

"""Repository hygiene checks.

Enforces English-only text, no traces of AI tooling (notices, trailers, chat links,
model names, tool configuration files, bot identities), clean commit identities, and no
local paths or leaked secrets.

Modes:
  check_hygiene.py                    tracked files, commits (BASE_SHA..HEAD_SHA), PR text
  check_hygiene.py --commit-msg FILE  additionally checks a commit message file
  check_hygiene.py --pre-commit       tracked files, the local author identity, and the
                                      current branch name

Environment:
  BASE_SHA, HEAD_SHA       commit range to check
  PR_TITLE, PR_BODY        pull request text to check
  PR_BRANCH                pull request source branch name to check
  HYGIENE_STRICT_AUTHORS   "1" to accept only the maintainer's commit identities
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# Identities accepted when HYGIENE_STRICT_AUTHORS=1 (the maintainer's own pull requests).
MAINTAINER_EMAILS = {
    "88090358+hunterewok@users.noreply.github.com",
    "noreply@github.com",
}

# Bot identities that are always accepted.
ALLOWED_BOT_EMAILS = {
    "49699333+dependabot[bot]@users.noreply.github.com",
    "41898282+github-actions[bot]@users.noreply.github.com",
}

# Commit identities of AI coding tools, rejected for every contributor.
BLOCKED_EMAIL_RE = re.compile(
    r"(?i)(?:@anthropic\.com|@openai\.com|@cursor\.(?:com|sh)|@aider\.chat|@codeium\.com"
    r"|@windsurf\.com|@cognition\.ai|@devin\.ai|@tabnine\.com|@sourcegraph\.com"
    r"|copilot|claude|codex|\[bot\]@)"
)

# Allowed non-ASCII characters (standard typographic punctuation and math/symbols).
ALLOWED_NON_ASCII = set("—–‘’“”•…·§©®™°±×÷≠≤≥→←↔⇒⇔")

# Forbidden scripts (Cyrillic, CJK, Arabic, Hebrew, etc.).
FORBIDDEN_SCRIPT_RE = re.compile(
    r"[Ѐ-ӿ"  # Cyrillic
    r"Ԁ-ԯ"  # Cyrillic Supplement
    r"֐-׿"  # Hebrew
    r"؀-ۿ"  # Arabic
    r"぀-ヿ"  # Hiragana / Katakana
    r"一-鿿"  # CJK Unified Ideographs
    r"가-힯]"  # Hangul
)

_TOOL = (
    r"(?:ai|claude|anthropic|chatgpt|openai|gpt|copilot|codex|gemini|cursor|windsurf|aider"
    r"|devin|codeium|tabnine|cody|llm|antigravity|an?\s+(?:ai|llm|assistant|language\s+model))"
)

AI_TRACE_PATTERNS = [
    # Notices such as "Generated with [Tool](link)" or "Co-written by an AI".
    (re.compile(rf"(?i)\b(?:generated|made|written|created|authored|assisted|produced|drafted)"
                rf"\s+(?:by|with|using|via)\s+[\[(*_`\s]*{_TOOL}\b"), "AI generation notice"),
    (re.compile(r"(?i)\bai[- ](?:generated|assisted|written|authored|powered\s+coding)\b"), "AI generation notice"),
    (re.compile(r"(?i)\bas\s+an\s+ai\b"), "AI assistant phrasing"),
    # Product and vendor names.
    (re.compile(r"(?i)\b(?:claude|anthropic|chatgpt|openai|copilot|codex|antigravity)\b"), "AI tool or vendor name"),
    (re.compile(r"(?i)\b(?:cursor|windsurf|devin|codeium|tabnine)\s+(?:ai|agent|ide|chat|composer|rules)\b"),
     "AI tool name"),
    (re.compile(r"(?i)\baider\.chat\b"), "AI tool name"),
    (re.compile(r"(?i)\b(?:llms?|large\s+language\s+models?|language\s+model)\b"), "language model reference"),
    # Model identifiers.
    (re.compile(r"(?i)\b(?:opus|sonnet|haiku)[ -]?\d"), "AI model identifier"),
    (re.compile(r"(?i)\bgemini[ -]?(?:\d+(?:\.\d+)?|cli|code\s+assist|pro|flash|ultra)\b"), "AI model identifier"),
    (re.compile(r"(?i)\bgpt-?\d"), "AI model identifier"),
    # Chat and session links.
    (re.compile(r"(?i)chatgpt\.com/"), "chat link"),
    (re.compile(r"(?i)chat\.openai\.com/"), "chat link"),
    (re.compile(r"(?i)gemini\.google\.com/"), "chat link"),
    (re.compile(r"(?i)aistudio\.google\.com/"), "chat link"),
    (re.compile(r"(?i)conversation://"), "internal conversation URI"),
    # Trailers that tools append to commit messages.
    (re.compile(r"(?im)^\s*(?:[a-z]+-session|ai-assisted|assisted-by|generated-by|co-developed-by)\s*:"),
     "AI tool trailer"),
]

SECRET_AND_PATH_PATTERNS = [
    (re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), "private key header"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "API secret key"),
    (re.compile(r"(?:/home|/Users)/[A-Za-z0-9._-]+/"), "local home directory path"),
    (re.compile(r"(?i)\b[A-Z]:\\Users\\"), "local home directory path"),
]

# Configuration files and directories of AI coding tools.
FORBIDDEN_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:claude\.md|agents\.md|gemini\.md|\.claude|\.cursor|\.cursorrules|\.cursorignore"
    r"|\.aider[^/]*|\.windsurf[^/]*|\.clinerules|\.cline|\.continue|\.codex|\.junie|\.roo[^/]*"
    r"|\.gemini|copilot-instructions\.md|\.copilot)(?:/|$)"
)

# Branch namespaces that AI coding tools create by default.
FORBIDDEN_BRANCH_RE = re.compile(
    r"(?i)(?:^|/)(?:claude|anthropic|codex|copilot|chatgpt|openai|gemini|cursor|windsurf|aider|devin"
    r"|codeium|tabnine|cody|jules|sweep|ai|llm|agent|bot)(?:[-_/]|$)"
)

CO_AUTHOR_RE = re.compile(r"(?im)^co-authored-by:\s*(.*?)\s*<([^>]*)>\s*$")

# Files that legitimately mention forbidden patterns as part of the hygiene rule itself.
SELF_EXEMPT = {
    ".github/scripts/check_hygiene.py",
    ".github/scripts/test_check_hygiene.py",
}


def check_text(label: str, text: str, errors: list[str], *, check_scripts: bool = True) -> None:
    if check_scripts:
        for idx, line in enumerate(text.splitlines(), 1):
            m = FORBIDDEN_SCRIPT_RE.search(line)
            if m:
                errors.append(f"{label}:{idx}: non-English script character {m.group(0)!r} found")
                continue
            for ch in line:
                if ord(ch) > 127 and ch not in ALLOWED_NON_ASCII:
                    errors.append(f"{label}:{idx}: unexpected non-ASCII character {ch!r} (U+{ord(ch):04X})")
                    break

    for pattern, desc in AI_TRACE_PATTERNS + SECRET_AND_PATH_PATTERNS:
        m = pattern.search(text)
        if m:
            errors.append(f"{label}: forbidden {desc}: {m.group(0)!r}")


def check_identity(label: str, name: str, email: str, errors: list[str], *, strict: bool) -> None:
    email = email.strip().lower()
    if email in ALLOWED_BOT_EMAILS:
        return
    if BLOCKED_EMAIL_RE.search(email):
        errors.append(f"{label}: AI tool or bot identity <{email}>")
    elif strict and email not in MAINTAINER_EMAILS:
        errors.append(f"{label}: identity <{email}> is not the maintainer's")
    check_text(f"{label} name", name, errors)


def check_branch(label: str, branch: str, errors: list[str]) -> None:
    branch = branch.strip()
    if not branch:
        return
    m = FORBIDDEN_BRANCH_RE.search(branch)
    if m:
        errors.append(f"{label} {branch!r}: branch name points at an AI tool ({m.group(0).strip('/')!r})")
    check_text(label, branch, errors)


def check_local_branch(errors: list[str]) -> None:
    res = subprocess.run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"], capture_output=True, text=True)
    check_branch("current branch", res.stdout, errors)


def normalize_path(rel: str) -> str:
    return rel[2:] if rel.startswith("./") else rel


def check_paths(paths: list[str], errors: list[str]) -> None:
    for rel in paths:
        if FORBIDDEN_PATH_RE.search(rel):
            errors.append(f"{rel}: AI tool configuration file must not be committed")
        check_text(f"path {rel}", rel, errors)


def tracked_files() -> list[str]:
    res = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True)
    return [normalize_path(p.decode("utf-8", errors="replace")) for p in res.stdout.split(b"\0") if p]


def check_tracked_files(errors: list[str]) -> None:
    paths = tracked_files()
    check_paths(paths, errors)
    for rel in paths:
        if rel in SELF_EXEMPT:
            continue
        p = Path(rel)
        if not p.is_file():
            continue
        raw = p.read_bytes()
        if b"\x00" in raw:
            continue  # Binary file
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{rel}: file is not valid UTF-8")
            continue
        check_text(rel, text, errors)


def check_commits(base: str, head: str, errors: list[str], *, strict: bool) -> None:
    sep = "\x1e"
    field_sep = "\x1f"
    fmt = f"%H{field_sep}%an{field_sep}%ae{field_sep}%cn{field_sep}%ce{field_sep}%B{sep}"
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
        parts = record.split(field_sep, 5)
        if len(parts) != 6:
            continue
        sha, author_name, author_email, committer_name, committer_email, msg = parts
        short = sha[:9]
        check_identity(f"commit {short} author", author_name, author_email, errors, strict=strict)
        check_identity(f"commit {short} committer", committer_name, committer_email, errors, strict=strict)
        for name, email in CO_AUTHOR_RE.findall(msg):
            check_identity(f"commit {short} co-author", name, email, errors, strict=strict)
        check_text(f"commit {short}", msg, errors)


def check_local_identity(errors: list[str]) -> None:
    res = subprocess.run(["git", "var", "GIT_AUTHOR_IDENT"], capture_output=True, text=True)
    m = re.match(r"(.*?)\s*<([^>]*)>", res.stdout)
    if m:
        check_identity("local git author", m.group(1), m.group(2), errors, strict=False)


def main(argv: list[str]) -> int:
    errors: list[str] = []
    strict = os.environ.get("HYGIENE_STRICT_AUTHORS", "").strip() == "1"
    check_tracked_files(errors)

    base = os.environ.get("BASE_SHA", "").strip()
    head = os.environ.get("HEAD_SHA", "").strip()
    if base and head and base != "0" * 40:
        check_commits(base, head, errors, strict=strict)

    pr_title = os.environ.get("PR_TITLE", "")
    pr_body = os.environ.get("PR_BODY", "")
    if pr_title:
        check_text("PR title", pr_title, errors)
    if pr_body:
        check_text("PR description", pr_body, errors)
    check_branch("PR branch", os.environ.get("PR_BRANCH", ""), errors)

    if len(argv) == 2 and argv[0] == "--commit-msg":
        msg = Path(argv[1]).read_text(encoding="utf-8", errors="replace")
        # Comment lines are stripped by git before the commit is recorded.
        msg = "\n".join(line for line in msg.splitlines() if not line.startswith("#"))
        check_text("commit message", msg, errors)
        for name, email in CO_AUTHOR_RE.findall(msg):
            check_identity("commit message co-author", name, email, errors, strict=False)
    elif argv == ["--pre-commit"]:
        check_local_identity(errors)
        check_local_branch(errors)

    if errors:
        print("Hygiene check failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("Hygiene check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
