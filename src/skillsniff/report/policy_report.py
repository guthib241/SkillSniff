"""Rendering for ``skillsniff policy check``."""

from __future__ import annotations

import sys
from typing import TextIO

from skillsniff.policy.engine import Decision, Outcome, Policy
from skillsniff.report.style import Style, width, wrap

_OUTCOME_STYLE = {Outcome.ALLOW: "ok", Outcome.REVIEW: "medium", Outcome.DENY: "critical"}


def render(
    policy: Policy, decisions: list[Decision], stream: TextIO | None = None, *, color: bool = True
) -> None:
    out = stream or sys.stdout
    style = Style(color)
    line_width = width()

    def emit(text: str = "") -> None:
        print(text, file=out)

    emit()
    emit(f"  {style('policy', 'dim')} {style(policy.name, 'bold')}")
    if policy.description:
        for line in wrap(policy.description, line_width - 4, "  "):
            emit(style(line, "dim"))
    emit()

    for decision in decisions:
        badge = style(f" {decision.outcome.value} ", _OUTCOME_STYLE[decision.outcome])
        emit(f"  {style(decision.skill, 'bold')}  {badge}")
        if not decision.clauses:
            emit(f"    {style('no policy clause matched', 'dim')}")
        for clause in decision.clauses:
            marker = style(clause.outcome.value.rjust(6), _OUTCOME_STYLE[clause.outcome])
            emit(f"    {marker}  {style(clause.key, 'bold')} = {clause.value}")
            for line in wrap(clause.reason, line_width - 14, "            "):
                emit(style(line, "dim"))
        emit()

    emit(style("  " + "─" * (line_width - 4), "dim"))
    denied = [d for d in decisions if d.outcome is Outcome.DENY]
    review = [d for d in decisions if d.outcome is Outcome.REVIEW]
    if denied:
        emit(f"  {style('DENIED', 'critical')} — {len(denied)} skill(s) violate the policy")
    elif review:
        emit(f"  {style('REVIEW', 'medium')} — {len(review)} skill(s) need human approval")
    else:
        emit(f"  {style('ALLOWED', 'ok')} — every skill satisfies the policy")
    emit()
