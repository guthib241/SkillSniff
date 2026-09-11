#!/usr/bin/env python3
"""Evaluate SkillSniff against skills this project did not write.

The bundled benchmark (``skillsniff benchmark``) is a regression suite: its
cases were written alongside the rules they exercise, so a perfect score there
measures self-consistency, not generalisation. This harness is the counterweight
— it runs the scanner over public corpora authored by other people and reports
what happened, including the parts that look bad.

Corpora are pinned to a commit so the numbers are replayable. Nothing here is
executed: skills are cloned and read, never run.

    python scripts/external_eval.py            # scan, print the report
    python scripts/external_eval.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from skillsniff.core.config import Config  # noqa: E402
from skillsniff.engine import load_rules, scan  # noqa: E402


@dataclass(frozen=True)
class Corpus:
    """One pinned external source of skills."""

    key: str
    url: str
    revision: str
    #: What the corpus's own publisher says about it. This is the label; we do
    #: not relabel other people's skills to suit the result.
    expectation: str
    note: str


CORPORA = (
    Corpus(
        key="anthropics/skills",
        url="https://github.com/anthropics/skills.git",
        revision="34040c9c568585f6929bedeaad110ad08f079624",
        expectation="benign",
        note=(
            "Anthropic's own published skills. Treated as the false-positive "
            "corpus: any BLOCK here is a defect in SkillSniff, not in the skill."
        ),
    ),
    Corpus(
        key="snyk-labs/toxicskills-goof",
        url="https://github.com/snyk-labs/toxicskills-goof.git",
        revision="80ce2e06f52fd384163c4bd6778676019723773c",
        expectation="contains-malicious",
        note=(
            "Snyk's published ToxicSkills demo corpus. Its README names the "
            "fake Vercel skill as the malicious sample, which posts `uname -a` "
            "to a paste site. Per-skill labels are not published for the rest, "
            "so this measures detection on the one labelled sample plus the "
            "verdict spread — it is not a recall figure."
        ),
    ),
)


def clone(corpus: Corpus, into: Path) -> Path:
    target = into / corpus.key.replace("/", "__")
    if target.exists():
        return target
    # Both argument lists are built from the module-level CORPORA constants, so
    # there is no untrusted input here and no shell involved. `git` is resolved
    # from PATH deliberately: this is a developer tool, not part of the scanner.
    clone = ["git", "clone", "--quiet", corpus.url, str(target)]
    checkout = ["git", "-C", str(target), "checkout", "--quiet", corpus.revision]
    subprocess.run(clone, check=True, capture_output=True)  # noqa: S603
    subprocess.run(checkout, check=True, capture_output=True)  # noqa: S603
    return target


def evaluate(corpus: Corpus, path: Path) -> dict:
    result = scan(path, Config())
    verdicts = Counter(s.risk.verdict.value for s in result.skills)
    rules = Counter(
        f.rule_id
        for s in result.skills
        for f in s.findings
        if f.severity.value in ("critical", "high")
    )
    return {
        "corpus": corpus.key,
        "revision": corpus.revision,
        "expectation": corpus.expectation,
        "note": corpus.note,
        "skills": len(result.skills),
        "overall": result.verdict.value,
        "verdicts": dict(verdicts),
        "counts": result.counts(),
        "top_rules": rules.most_common(10),
        "per_skill": [
            {
                "name": s.name,
                "verdict": s.risk.verdict.value,
                "critical": sum(1 for f in s.findings if f.severity.value == "critical"),
            }
            for s in result.skills
        ],
    }


def render(reports: list[dict]) -> str:
    lines: list[str] = []
    for report in reports:
        lines.append(f"## {report['corpus']} @ {report['revision'][:12]}")
        lines.append("")
        lines.append(report["note"])
        lines.append("")
        lines.append(f"- skills scanned: **{report['skills']}**")
        lines.append(f"- overall verdict: **{report['overall']}**")
        spread = ", ".join(f"{k} {v}" for k, v in sorted(report["verdicts"].items()))
        lines.append(f"- verdict spread: {spread}")
        blocked = report["verdicts"].get("BLOCK", 0)
        if report["expectation"] == "benign":
            rate = blocked / report["skills"] if report["skills"] else 0.0
            lines.append(f"- **false BLOCK rate: {blocked}/{report['skills']} = {rate:.3f}**")
        lines.append("")
        if report["top_rules"]:
            lines.append("| rule | critical+high findings |")
            lines.append("|---|---|")
            for rule, count in report["top_rules"]:
                lines.append(f"| `{rule}` | {count} |")
            lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="write the raw report here")
    parser.add_argument("--cache", type=Path, help="directory to clone into")
    args = parser.parse_args()

    load_rules()
    cache = args.cache or Path(tempfile.mkdtemp(prefix="skillsniff-external-"))
    cache.mkdir(parents=True, exist_ok=True)

    reports = []
    for corpus in CORPORA:
        try:
            path = clone(corpus, cache)
        except subprocess.CalledProcessError as error:
            print(f"could not fetch {corpus.key}: {error}", file=sys.stderr)
            return 2
        reports.append(evaluate(corpus, path))

    print(render(reports))
    if args.json:
        args.json.write_text(json.dumps(reports, indent=2), encoding="utf-8")
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
