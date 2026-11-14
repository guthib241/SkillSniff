#!/usr/bin/env python3
"""Render a holdout_eval.py summary.json as the Markdown tables in docs/EXTERNAL_VALIDATION.md.

Kept separate from the measurement so the published tables are generated
from the recorded results rather than transcribed by hand.

    python scripts/render_holdout.py docs/results/holdout-2026-11-13/summary.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RISK_NAMES = {
    "T01": "Skill instruction hijacking",
    "T02": "Agent memory poisoning",
    "T03": "Remote payload retrieval and execution",
    "T04": "Embedded malicious code",
    "T05": "Unauthorized access and privilege escalation",
    "T06": "System persistence",
    "T07": "Tool hijacking and spoofing",
    "T08": "Insecure dependencies",
    "T09": "Insecure skill coding practices",
}


def rate(cell: dict) -> str:
    if not cell["total"]:
        return "—"
    low, high = cell["wilson95"]
    return f"{cell['rate']:.3f} ({cell['hits']}/{cell['total']}) [{low:.3f}, {high:.3f}]"


def headline(m: dict) -> list[str]:
    return [
        "| Metric | Value, Wilson 95% CI |",
        "| --- | --- |",
        f"| **Malicious recall** (blocked) | **{rate(m['malicious_recall'])}** |",
        f"| Non-normal recall (blocked or flagged) | {rate(m['non_normal_recall'])} |",
        f"| False BLOCK rate on normal cases | {rate(m['false_block_rate_on_normal'])} |",
        f"| Normal cases flagged (BLOCK or REVIEW) | {rate(m['flagged_rate_on_normal'])} |",
        f"| Accuracy (three-way) | {m['accuracy']:.3f} |",
        f"| Macro-F1 (three-way) | {m['macro_f1']:.3f} |",
        f"| Cases | {m['cases']} |",
    ]


def confusion(m: dict) -> list[str]:
    labels = ("normal", "suspicious", "malicious")
    out = ["| gold \\ predicted | normal | suspicious | malicious |", "| --- | --- | --- | --- |"]
    for gold in labels:
        out.append(f"| {gold} | " + " | ".join(str(m["confusion"][gold][p]) for p in labels) + " |")
    return out


def verdicts(m: dict) -> list[str]:
    order = ("BLOCK", "REVIEW", "CAUTION", "CLEAR", "INCONCLUSIVE", "ERROR", "NO_SKILL")
    out = ["| gold | " + " | ".join(order) + " |", "| --- |" + " --- |" * len(order)]
    for gold, counts in m["verdicts_by_gold"].items():
        out.append(f"| {gold} | " + " | ".join(str(counts.get(v, 0)) for v in order) + " |")
    return out


def breakdown(rows: dict, names: dict | None = None) -> list[str]:
    out = [
        "| Group | Cases | Malicious recall | Non-normal recall | False BLOCK on normal |",
        "| --- | --- | --- | --- | --- |",
    ]
    for key, cell in rows.items():
        label = f"`{key}` {names[key]}" if names and key in names else f"`{key}`"
        out.append(
            f"| {label} | {cell['cases']} | {rate(cell['malicious_recall'])} | "
            f"{rate(cell['non_normal_recall'])} | {rate(cell['false_block_rate_on_normal'])} |"
        )
    return out


def main() -> int:
    summary = json.loads(Path(sys.argv[1]).read_text())
    lines = [f"Scanned commit `{summary['scanned_commit']}`, {summary['started']} to {summary['finished']}.", ""]
    stb = summary.get("skilltrustbench")
    if stb:
        lines += [f"### SkillTrustBench — `{stb['dataset']}`", "",
                  f"Headline figures exclude {stb['headline_excludes']}.", ""]
        lines += [*headline(stb["headline"]), "", "Verdicts by expert label:", ""]
        lines += [*verdicts(stb["headline"]), "", "Confusion matrix (official evaluator mapping):", ""]
        lines += [*confusion(stb["headline"]), "", "By source:", ""]
        lines += [*breakdown(stb["by_source"]), "", "By risk label (a case can carry several):", ""]
        lines += [*breakdown(stb["by_risk_label"], RISK_NAMES), ""]
        lines += ["Contaminated cases, reported on their own:", ""]
        lines += [*(f"- `{c['id']}` ({c['gold']}): {c['verdict']}" for c in stb["contaminated_cases"]), ""]
    claw = summary.get("clawhub")
    if claw:
        lines += [f"### ClawHub — `{claw['dataset']}`", "", f"Measures {claw['measures']}.", ""]
        lines += [*headline(claw["combined"]), "", "Verdicts by ClawScan label:", ""]
        lines += [*verdicts(claw["combined"]), ""]
        for split, m in claw["per_split"].items():
            lines += [f"`{split}`: malicious recall {rate(m['malicious_recall'])}; "
                      f"false BLOCK on clean {rate(m['false_block_rate_on_normal'])}; {m['cases']} rows.", ""]
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
