"""Markdown output, sized for a GitHub job summary or a pull-request comment.

Kept compact deliberately: a summary nobody scrolls through is a summary nobody
reads. Full detail belongs in the JSON or SARIF artifact.
"""

from __future__ import annotations

import sys
from typing import TextIO

from skillsniff.model.finding import Severity
from skillsniff.model.result import RiskBand, ScanResult

_VERDICT_ICON = {
    "BLOCK": "🛑",
    "REVIEW": "⚠️",
    "CAUTION": "🟡",
    "CLEAR": "✅",
    "INCONCLUSIVE": "❔",
}


def render(result: ScanResult, stream: TextIO | None = None, *, max_findings: int = 20) -> None:
    out = stream or sys.stdout

    def emit(text: str = "") -> None:
        print(text, file=out)

    verdict = result.verdict
    counts = result.counts()

    emit(f"## {_VERDICT_ICON.get(verdict.value, '')} SkillSniff: {verdict.value}")
    emit()
    emit(f"_{verdict.summary}_")
    emit()
    emit(
        f"**{len(result.skills)} skill(s) scanned** · "
        + " · ".join(f"{n} {name}" for name, n in counts.items() if n)
        + (" · no findings" if not any(counts.values()) else "")
    )
    emit()

    if len(result.skills) > 1:
        emit("| Skill | Verdict | Security | Capability | Supply chain | Coverage |")
        emit("| --- | --- | --- | --- | --- | --- |")
        for skill in result.skills:
            risk = skill.risk
            emit(
                f"| `{skill.name}` | {_VERDICT_ICON.get(risk.verdict.value, '')} "
                f"{risk.verdict.value} | {_band(risk.band('security'))} | "
                f"{_band(risk.band('capability'))} | {_band(risk.band('supply_chain'))} | "
                f"{skill.coverage.confidence} |"
            )
        emit()

    for skill in result.skills:
        actionable = [f for f in skill.findings if f.severity.rank <= Severity.LOW.rank]
        if not actionable:
            continue
        emit(f"<details><summary><code>{skill.name}</code> — {len(actionable)} finding(s)</summary>")
        emit()
        for finding in actionable[:max_findings]:
            location = finding.location
            emit(
                f"- **{finding.rule_id}** ({finding.severity.value}"
                + (f", {finding.confidence.value} confidence" if finding.confidence.value != "high" else "")
                + f") — {finding.title}"
            )
            emit(f"  - `{location}`" + (f" — {finding.message}" if finding.message else ""))
            if finding.remediation:
                emit(f"  - _Fix:_ {finding.remediation}")
        if len(actionable) > max_findings:
            emit(f"- _… and {len(actionable) - max_findings} more_")
        emit()

        undeclared = sorted(c.value for c in skill.capabilities.undeclared)
        if undeclared:
            emit(f"**Undeclared capabilities:** {', '.join(f'`{c}`' for c in undeclared)}")
            emit()
        if skill.coverage.gaps:
            emit(f"**Coverage gaps:** {len(skill.coverage.gaps)} — analysis confidence {skill.coverage.confidence}")
            emit()
        emit("</details>")
        emit()

    emit("---")
    emit(
        "<sub>A clean result means no issues were detected by the enabled checks. "
        "It is not a guarantee that the skill is safe.</sub>"
    )


def _band(band: RiskBand) -> str:
    return "—" if band is RiskBand.NONE else band.value
