#!/usr/bin/env python3
"""Fail if a figure appears in the README without an entry in CLAIMS.md.

A number with no derivation is the fastest way to lose a reader who checks, and
this project's argument rests on reporting how often it is wrong. That argument
does not survive one stale figure, so the check is mechanical rather than a
matter of remembering.

This caught real drift the first time it ran: adding one rule left "87 rules"
in two places, "41-case corpus" in five files, and two documents disagreeing
about the median scan time.

    python scripts/claims_lint.py            # check
    python scripts/claims_lint.py --list     # print what it extracted

Scope is deliberately narrow. It checks the README, because that is what a
reader sees first. Numbers the check would only ever flag as noise — version
strings, Python versions, spec and CWE identifiers, dates, list markers — are
excluded by the patterns below, not by a per-number allowlist, so the exclusion
cannot quietly grow to cover a real claim.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Figures worth checking: a decimal, a percentage, or an integer of 2+ digits.
#: Single digits are excluded — they are almost always prose ("the three
#: rulesets"), and a claim that rests on a single digit is not the failure mode
#: this guards against.
FIGURE = re.compile(r"\b\d+\.\d+\b|\b\d[\d,]*%|\b\d[\d,]{1,}\b")

#: Spans whose numbers are not claims. Each is a *shape*, not a value, so a new
#: real claim cannot hide inside one.
IGNORED_SPANS = (
    re.compile(r"```.*?```", re.DOTALL),          # fenced code and sample output
    re.compile(r"`[^`\n]*`"),                     # inline code, flags, paths
    re.compile(r"\]\([^)]*\)"),                   # link targets
    re.compile(r"https?://\S+"),                  # bare URLs
    re.compile(r"^\s*\d+\.\s", re.MULTILINE),     # ordered-list markers
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),         # ISO dates
    re.compile(r"\bCWE-\d+\b"),                   # CWE identifiers
    re.compile(r"\bLLM\d+\b"),                    # OWASP LLM identifiers
    re.compile(r"\bv?\d+\.\d+\.\d+\b"),           # semantic versions
    re.compile(r"\bPython 3\.\d+\b"),             # interpreter versions
    re.compile(r"\bSARIF \d+\.\d+\.\d+\b"),       # spec version
)


def strip_ignored(text: str) -> str:
    """Blank out spans whose numbers are not claims, preserving offsets."""
    for pattern in IGNORED_SPANS:
        text = pattern.sub(lambda m: " " * len(m.group(0)), text)
    return text


def figures_in(text: str) -> set[str]:
    return {m.group(0).rstrip("%") for m in FIGURE.finditer(strip_ignored(text))}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print extracted figures")
    args = parser.parse_args()

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    claims_path = REPO_ROOT / "CLAIMS.md"
    if not claims_path.exists():
        print("CLAIMS.md is missing; every figure in the README needs a source.", file=sys.stderr)
        return 1
    claims = claims_path.read_text(encoding="utf-8")

    found = figures_in(readme)
    if args.list:
        for figure in sorted(found, key=lambda v: (len(v), v)):
            print(figure)
        return 0

    # A figure is accounted for if it appears anywhere in CLAIMS.md, including
    # inside its code spans and citations — CLAIMS.md is the ledger, so a
    # number appearing there at all means somebody wrote down where it is from.
    missing = sorted(f for f in found if f not in claims)
    if missing:
        print("README figures with no CLAIMS.md entry:", file=sys.stderr)
        for figure in missing:
            for number, line in enumerate(readme.splitlines(), 1):
                if figure in line:
                    print(f"  {figure!r}  README.md:{number}: {line.strip()[:96]}", file=sys.stderr)
                    break
        print(
            "\nAdd each to CLAIMS.md with how it was obtained (MEASURED / CITED / DERIVED),\n"
            "or remove it from the README. A figure with no derivation should not ship.",
            file=sys.stderr,
        )
        return 1

    print(f"claims lint: {len(found)} README figures, all present in CLAIMS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
