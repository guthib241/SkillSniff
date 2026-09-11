"""Human-readable terminal output.

Findings are ordered by severity, then confidence, so the thing most worth
acting on is at the top and the reader can stop whenever they choose. Every
finding shows its evidence location, and the ``--explain`` detail is one command
away rather than inlined, because a wall of remediation text buries the findings.

Coverage is always printed, even on a clean scan. "No issues detected" means
nothing without "and here is how much of the artifact that covers".
"""

from __future__ import annotations

import sys
from typing import TextIO

from skillsniff.model.finding import Confidence, Finding, Severity
from skillsniff.model.result import RiskBand, ScanResult, SkillResult
from skillsniff.report.style import Style, truncate, width, wrap

_SEVERITY_GLYPH = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: " !",
    Severity.MEDIUM: " ~",
    Severity.LOW: " ·",
    Severity.INFO: " i",
}


def render(
    result: ScanResult,
    stream: TextIO | None = None,
    *,
    color: bool = True,
    quiet: bool = False,
    verbose: bool = False,
    min_severity: Severity = Severity.INFO,
    show_capabilities: bool = True,
) -> None:
    out = stream or sys.stdout
    style = Style(color)
    line_width = width()

    def emit(text: str = "") -> None:
        print(text, file=out)

    if not quiet:
        emit()
        emit(
            f"  {style('SkillSniff', 'bold')} {result.tool_version} "
            f"{style('· security, trust and capability analysis for agent skills', 'dim')}"
        )
        emit()

    for skill in result.skills:
        _render_skill(
            skill,
            emit,
            style,
            line_width,
            quiet=quiet,
            verbose=verbose,
            min_severity=min_severity,
            show_capabilities=show_capabilities,
        )

    _render_summary(result, emit, style, line_width, quiet=quiet)


def _render_skill(
    skill: SkillResult,
    emit,
    style: Style,
    line_width: int,
    *,
    quiet: bool,
    verbose: bool,
    min_severity: Severity,
    show_capabilities: bool,
) -> None:
    verdict = skill.risk.verdict
    badge = style.verdict(verdict, f" {verdict.value} ")
    emit(f"  {style(skill.name, 'bold')}  {badge}  {style(skill.risk.summary, 'dim')}")

    if not quiet:
        bands = [
            f"{d.label.lower()} {style.band(d.band)}"
            for d in skill.risk.dimensions.values()
            if d.band is not RiskBand.NONE
        ]
        if bands:
            emit(f"    {style('risk:', 'dim')} " + style("·", "dim").join(f" {b} " for b in bands))

    visible = [f for f in skill.findings if f.severity.rank <= min_severity.rank]
    if not visible:
        emit(f"    {style('no findings from the enabled checks', 'dim')}")
    for finding in visible:
        _render_finding(finding, emit, style, line_width, quiet=quiet, verbose=verbose)

    if show_capabilities and not quiet:
        _render_capabilities(skill, emit, style)

    _render_coverage(skill, emit, style, verbose=verbose)
    emit()


def _render_finding(
    finding: Finding, emit, style: Style, line_width: int, *, quiet: bool, verbose: bool
) -> None:
    glyph = style.severity(finding.severity, _SEVERITY_GLYPH[finding.severity])
    rule = style(finding.rule_id, "bold")
    confidence = (
        "" if finding.confidence is Confidence.HIGH else style(f" [{finding.confidence.value} confidence]", "dim")
    )
    advisory = style(" [advisory]", "dim") if finding.advisory else ""

    emit(f"    {glyph} {rule}  {style(finding.title, 'bold')}{confidence}{advisory}")
    for line in wrap(finding.message, line_width - 10, "         "):
        emit(line)

    for evidence in finding.evidence[: (4 if verbose else 2)]:
        location = style(evidence.location, "underline")
        detail = ""
        if evidence.decode_chain:
            detail += style(f"  ({evidence.decode_chain})", "medium")
        if evidence.note:
            detail += style(f"  — {truncate(evidence.note, 60)}", "dim")
        emit(f"         {location}{detail}")
        if evidence.excerpt:
            emit(f"           {style(truncate(evidence.excerpt, line_width - 14), 'dim')}")

    if not quiet and finding.remediation:
        for line in wrap(f"fix: {finding.remediation}", line_width - 10, "         "):
            emit(style(line, "dim"))


def _render_capabilities(skill: SkillResult, emit, style: Style) -> None:
    surface = skill.capabilities
    if not surface.all:
        return
    privileged = sorted(surface.privileged, key=lambda c: c.value)
    if not privileged:
        return
    undeclared = surface.undeclared
    parts = []
    for capability in privileged:
        marker = style("+", "high") if capability in undeclared else style("·", "dim")
        parts.append(f"{marker}{capability.value}")
    emit(f"    {style('capabilities:', 'dim')} {' '.join(parts)}")
    if undeclared & set(privileged):
        emit(f"    {style('(+ marks a capability the skill does not declare)', 'dim')}")


def _render_coverage(skill: SkillResult, emit, style: Style, *, verbose: bool) -> None:
    coverage = skill.coverage
    confidence_style = {"HIGH": "ok", "MEDIUM": "medium", "LOW": "high"}[coverage.confidence]
    bits = [
        f"files {coverage.files_analyzed}/{coverage.files_discovered}",
    ]
    if coverage.archives_expanded:
        bits.append(f"archives {coverage.archives_expanded}")
    if coverage.encoded_regions:
        bits.append(f"encoded regions {coverage.encoded_regions}")
    bits.append(f"coverage {style(coverage.confidence, confidence_style)}")
    emit(f"    {style('analysed:', 'dim')} {style(' · ', 'dim').join(bits)}")

    if coverage.gaps:
        shown = coverage.gaps if verbose else coverage.gaps[:3]
        for gap in shown:
            emit(
                f"      {style('not analysed:', 'medium')} {gap['path']} "
                f"{style('(' + gap['reason'] + ')', 'dim')}"
            )
        if len(coverage.gaps) > len(shown):
            emit(f"      {style(f'… and {len(coverage.gaps) - len(shown)} more', 'dim')}")


def _render_summary(result: ScanResult, emit, style: Style, line_width: int, *, quiet: bool) -> None:
    emit(style("  " + "─" * (line_width - 4), "dim"))

    counts = result.counts()
    parts = [
        style(f"{n} {name}", name)
        for name, n in counts.items()
        if n and name != "info"
    ]
    summary = " · ".join(parts) if parts else style("no findings", "ok")

    emit(f"  {len(result.skills)} skill(s) · {result.rules_run} rules · {summary}")

    verdict = result.verdict
    emit(f"  Overall: {style.verdict(verdict, verdict.value)} — {result.summary}")

    if result.baseline_path:
        emit(
            f"  {style('baseline:', 'dim')} {result.baseline_suppressed} finding(s) suppressed "
            f"by {result.baseline_path}"
        )
        if result.baseline_stale:
            emit(
                style(
                    f"    {result.baseline_stale} baseline entr"
                    f"{'y' if result.baseline_stale == 1 else 'ies'} no longer match anything — "
                    "those findings are fixed and can be removed",
                    "dim",
                )
            )

    if not quiet:
        emit()
        emit(
            style(
                "  A clean result means no issues were detected by the enabled checks.",
                "dim",
            )
        )
        emit(style("  It is not a guarantee that the skill is safe.", "dim"))

    if result.errors:
        emit()
        emit(f"  {style('errors during analysis:', 'high')}")
        for error in result.errors[:10]:
            emit(f"    {truncate(error, line_width - 6)}")
    emit()
