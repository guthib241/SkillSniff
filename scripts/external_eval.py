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
import math
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
class Sample:
    """One labelled sample: a path, a ground-truth label, and its technique."""

    name: str
    relpath: str
    malicious: bool
    technique: str


@dataclass(frozen=True)
class LabelledCorpus:
    """A corpus with per-sample ground truth, for measuring recall.

    Labels come from the corpus publisher, never from this project. Where the
    publisher ships a machine-readable manifest it is read directly rather than
    transcribed, so the labels cannot drift toward a flattering reading.
    """

    key: str
    url: str
    revision: str
    licence: str
    note: str
    #: Set when the publisher ships labels we read at runtime.
    manifest: str = ""
    samples: tuple[Sample, ...] = ()


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


#: Techniques as the Trail of Bits README describes them. That repository
#: exists to subvert skill scanners, so these are adversarial by construction.
TRAILOFBITS = LabelledCorpus(
    key="trailofbits/overtly-malicious-skills",
    url="https://github.com/trailofbits/overtly-malicious-skills.git",
    revision="4ffbf9461ef0505f9ce76a0d3694a18ec33ea531",
    licence="no licence file (all rights reserved; read and scanned, never redistributed)",
    note=(
        "Four malicious skills built by the Trail of Bits ML Security team "
        "specifically to defeat skill scanners. Labels and technique "
        "descriptions are the repository README's own."
    ),
    samples=(
        Sample(
            "csv-summarizer",
            "skills/csv-summarizer",
            True,
            "claims to summarize a CSV; dumps the environment variable store",
        ),
        Sample(
            "context-loader",
            "skills/context-loader",
            True,
            "smuggles a script inside the XML archive underlying a hidden .docx",
        ),
        Sample(
            "simple-formatter",
            "skills/simple-formatter",
            True,
            "Python bytecode poisoning: a .pyc with no matching source steals env vars",
        ),
        Sample(
            "dev-env-setup",
            "skills/dev-env-setup",
            True,
            "prompt injection aimed at the scanner, to permit an npm registry overwrite",
        ),
    ),
)

#: kurtpayne ships expectations.json, so its labels are read at runtime.
SKILLSCAN = LabelledCorpus(
    key="kurtpayne/skillscan-security",
    url="https://github.com/kurtpayne/skillscan-security.git",
    revision="c2a2cc4dc67d8d23221c1ab3fb7aa7c7695f5f82",
    licence="Apache-2.0",
    note=(
        "Adversarial cases from a competing scanner, retired 2026-07-03 with "
        "the conclusion that static scanning of AI skills does not work as a "
        "security boundary. Labels read from tests/adversarial/expectations.json."
    ),
    manifest="tests/adversarial/expectations.json",
)

LABELLED = (TRAILOFBITS, SKILLSCAN)


def load_manifest_samples(corpus: LabelledCorpus, path: Path) -> tuple[Sample, ...]:
    """Read the publisher's own labels rather than transcribing them."""
    if not corpus.manifest:
        return corpus.samples
    entries = json.loads((path / corpus.manifest).read_text(encoding="utf-8"))
    out: list[Sample] = []
    for entry in entries:
        case = entry["case"]
        # "block" and "warn" are the publisher's malicious verdicts; "allow" is
        # its negative control.
        malicious = entry.get("verdict") in ("block", "warn")
        out.append(
            Sample(
                name=case,
                relpath=f"tests/adversarial/cases/{case}",
                malicious=malicious,
                technique=f"{entry.get('verdict')}, expects {entry.get('must_find') or 'no finding'}",
            )
        )
    return tuple(out)


def evaluate_labelled(corpus: LabelledCorpus, root: Path) -> dict:
    """Scan each labelled sample on its own and score against ground truth."""
    samples = load_manifest_samples(corpus, root)
    rows: list[dict] = []
    for sample in samples:
        target = root / sample.relpath
        verdict = "NOT_DISCOVERED"
        rules: list[str] = []
        coverage = ""
        in_domain = (target / "SKILL.md").exists() or any(target.rglob("SKILL.md"))
        if in_domain:
            result = scan(target, Config())
            if result.skills:
                # Worst verdict across the skills the sample contains.
                skill = min(result.skills, key=lambda s: s.risk.verdict.rank)
                verdict = skill.risk.verdict.value
                coverage = skill.coverage.confidence
                rules = sorted(
                    {
                        f.rule_id
                        for s in result.skills
                        for f in s.findings
                        if f.severity.value in ("critical", "high", "medium")
                    }
                )
        rows.append(
            {
                "name": sample.name,
                "malicious": sample.malicious,
                "technique": sample.technique,
                "in_domain": in_domain,
                "verdict": verdict,
                "coverage": coverage,
                "rules": rules,
            }
        )
    return {
        "corpus": corpus.key,
        "revision": corpus.revision,
        "licence": corpus.licence,
        "note": corpus.note,
        "samples": rows,
    }


def clone(corpus: Corpus | LabelledCorpus, into: Path) -> Path:
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


def wilson(hits: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval. A bare 0/n or n/n rate overstates its own precision."""
    if total == 0:
        return (0.0, 1.0)
    rate = hits / total
    denom = 1 + z * z / total
    centre = (rate + z * z / (2 * total)) / denom
    half = (z / denom) * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total))
    return (max(0.0, centre - half), min(1.0, centre + half))


def score(report: dict) -> dict:
    """Recall, coverage and misses for one labelled corpus."""
    rows = report["samples"]
    malicious = [r for r in rows if r["malicious"]]
    benign = [r for r in rows if not r["malicious"]]
    in_domain = [r for r in malicious if r["in_domain"]]

    blocked = [r for r in in_domain if r["verdict"] == "BLOCK"]
    flagged = [r for r in in_domain if r["verdict"] in ("BLOCK", "REVIEW")]
    inconclusive = [r for r in in_domain if r["verdict"] == "INCONCLUSIVE"]
    missed = [r for r in in_domain if r["verdict"] != "BLOCK"]
    not_discovered = [r for r in malicious if not r["in_domain"]]
    false_positives = [r for r in benign if r["verdict"] == "BLOCK"]

    rules = Counter(rule for r in in_domain for rule in r["rules"])
    return {
        **report,
        "n_malicious": len(malicious),
        "n_in_domain": len(in_domain),
        "n_blocked": len(blocked),
        "n_flagged": len(flagged),
        "n_inconclusive": len(inconclusive),
        "n_not_discovered": len(not_discovered),
        "recall_in_domain": len(blocked) / len(in_domain) if in_domain else 0.0,
        "recall_in_domain_ci": wilson(len(blocked), len(in_domain)),
        "recall_whole": len(blocked) / len(malicious) if malicious else 0.0,
        "recall_whole_ci": wilson(len(blocked), len(malicious)),
        "flagged_rate": len(flagged) / len(in_domain) if in_domain else 0.0,
        "misses": missed,
        "not_discovered": not_discovered,
        "false_positives": false_positives,
        "n_benign": len(benign),
        "rule_breakdown": rules.most_common(),
    }


def render_labelled(scored: list[dict]) -> str:
    lines: list[str] = ["# Recall against labelled malicious corpora", ""]
    total_block = total_in = total_mal = total_flag = 0

    for report in scored:
        lo, hi = report["recall_in_domain_ci"]
        lines += [
            f"## {report['corpus']} @ {report['revision'][:12]}",
            "",
            f"Licence: {report['licence']}",
            "",
            report["note"],
            "",
            f"- labelled malicious: {report['n_malicious']}"
            f" ({report['n_in_domain']} in-domain, {report['n_not_discovered']} no SKILL.md)",
            f"- **blocked: {report['n_blocked']}/{report['n_in_domain']}"
            f" = {report['recall_in_domain']:.3f}**  95% CI [{lo:.3f}, {hi:.3f}]",
            f"- flagged (BLOCK or REVIEW): {report['n_flagged']}/{report['n_in_domain']}"
            f" = {report['flagged_rate']:.3f}",
            f"- INCONCLUSIVE (not a detection): {report['n_inconclusive']}",
            f"- benign controls: {report['n_benign']}, false BLOCKs: {len(report['false_positives'])}",
            "",
        ]
        if report["rule_breakdown"]:
            lines += ["| rule | samples it fired on |", "|---|---|"]
            lines += [f"| `{r}` | {n} |" for r, n in report["rule_breakdown"]]
            lines.append("")
        if report["misses"]:
            lines += ["**Missed (not BLOCK):**", ""]
            for row in report["misses"]:
                lines.append(
                    f"- `{row['name']}` -> {row['verdict']}"
                    f" (coverage {row['coverage'] or 'n/a'}) - {row['technique']}"
                    + (f"; fired: {', '.join(row['rules'])}" if row["rules"] else "; nothing fired")
                )
            lines.append("")
        if report["not_discovered"]:
            lines.append(
                "**Not discovered (no SKILL.md, outside the input contract):** "
                + ", ".join(f"`{r['name']}`" for r in report["not_discovered"])
            )
            lines.append("")
        total_block += report["n_blocked"]
        total_in += report["n_in_domain"]
        total_mal += report["n_malicious"]
        total_flag += report["n_flagged"]

    lo, hi = wilson(total_block, total_in)
    wlo, whi = wilson(total_block, total_mal)
    lines += [
        "## Pooled",
        "",
        f"- **in-domain recall: {total_block}/{total_in} = "
        f"{(total_block / total_in if total_in else 0):.3f}**  95% CI [{lo:.3f}, {hi:.3f}]",
        f"- whole-corpus recall: {total_block}/{total_mal} = "
        f"{(total_block / total_mal if total_mal else 0):.3f}  95% CI [{wlo:.3f}, {whi:.3f}]",
        f"- flagged for a human: {total_flag}/{total_in} = "
        f"{(total_flag / total_in if total_in else 0):.3f}",
        "",
    ]
    return "\n".join(lines)


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

    scored = []
    for corpus in LABELLED:
        try:
            path = clone(corpus, cache)
        except subprocess.CalledProcessError as error:
            print(f"could not fetch {corpus.key}: {error}", file=sys.stderr)
            return 2
        scored.append(score(evaluate_labelled(corpus, path)))

    print(render(reports))
    print()
    print(render_labelled(scored))
    if args.json:
        args.json.write_text(
            json.dumps({"verdict_spread": reports, "recall": scored}, indent=2),
            encoding="utf-8",
        )
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
