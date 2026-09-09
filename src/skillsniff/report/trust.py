"""The trust report — the output of ``skillsniff inspect``.

This is the answer to "what can this skill really do?", written so that someone
who has not read the implementation can answer it. It leads with purpose and
capability rather than with findings, because the question a person actually has
before installing a skill is what it will be able to reach, not how many rules
it tripped.

Every section states its own limits. A capability section that lists nothing
must say whether that is because nothing was found or because nothing could be
read, and those are different claims.
"""

from __future__ import annotations

import sys
from typing import TextIO

from skillsniff.analysis.context import AnalysisContext
from skillsniff.analysis.external import TrustLevel
from skillsniff.analysis.graph import TrustGraph, render_tree
from skillsniff.model.capability import Capability, Source
from skillsniff.model.finding import Severity
from skillsniff.model.result import RiskBand, SkillResult
from skillsniff.report.style import Style, truncate, width, wrap

_CAPABILITY_ORDER = [
    ("Filesystem", (Capability.FS_READ, Capability.FS_WRITE, Capability.FS_DELETE)),
    ("Network", (Capability.NET_FETCH, Capability.NET_OUTBOUND, Capability.NET_LISTEN, Capability.NET_DNS)),
    ("Execution", (Capability.PROC_EXEC, Capability.SHELL_EXEC, Capability.CODE_EVAL)),
    ("Environment", (Capability.ENV_READ, Capability.ENV_WRITE)),
    ("Secrets", (Capability.SECRET_ACCESS, Capability.CREDENTIAL_HANDLING)),
    ("Supply chain", (Capability.PKG_INSTALL, Capability.REMOTE_INSTRUCTIONS)),
    ("Persistence", (Capability.PERSISTENCE, Capability.CONFIG_MODIFY, Capability.MEMORY_WRITE)),
    ("Agent", (Capability.TOOL_USE, Capability.GIT_WRITE)),
]


def render(
    skill: SkillResult,
    context: AnalysisContext,
    graph: TrustGraph,
    stream: TextIO | None = None,
    *,
    color: bool = True,
    verbose: bool = False,
) -> None:
    out = stream or sys.stdout
    style = Style(color)
    line_width = width()

    def emit(text: str = "") -> None:
        print(text, file=out)

    def heading(text: str) -> None:
        emit()
        emit(f"  {style(text.upper(), 'bold')}")
        emit(f"  {style('─' * min(len(text), line_width - 4), 'dim')}")

    # -- header -------------------------------------------------------------
    emit()
    verdict = skill.risk.verdict
    emit(f"  {style(skill.name, 'bold')}   {style.verdict(verdict, f' {verdict.value} ')}")
    if skill.version:
        emit(f"  {style('version ' + skill.version, 'dim')}")
    emit(f"  {style(skill.path, 'dim')}")

    # -- purpose ------------------------------------------------------------
    heading("Stated purpose")
    if skill.description:
        for line in wrap(skill.description, line_width - 6, "  "):
            emit(line)
    else:
        emit(f"  {style('none declared — the skill has no description', 'medium')}")

    # -- declared -----------------------------------------------------------
    heading("Declared permissions")
    if skill.declared_tools:
        for tool in skill.declared_tools:
            emit(f"    {style('⚙', 'dim')} {tool}")
    else:
        emit(
            f"  {style('no allowed-tools declared', 'medium')} "
            f"{style('— the skill is unrestricted by declaration', 'dim')}"
        )

    # -- capabilities -------------------------------------------------------
    heading("Inferred capabilities")
    surface = skill.capabilities
    if not surface.all:
        emit(f"  {style('none inferred from the analysed content', 'dim')}")
    else:
        undeclared = surface.undeclared
        for group_label, capabilities in _CAPABILITY_ORDER:
            present = [c for c in capabilities if c in surface.all]
            if not present:
                continue
            emit(f"    {style(group_label, 'bold')}")
            for capability in present:
                mark = style("undeclared", "high") if capability in undeclared else style("declared", "dim")
                sources = ", ".join(sorted(s.value for s in surface.sources_for(capability)))
                confidence = surface.best_confidence(capability)
                emit(
                    f"      {style('▶', 'dim')} {capability.label:38} "
                    f"{mark}  {style(f'via {sources} ({confidence.value} confidence)', 'dim')}"
                )
                if verbose:
                    for observation in surface.by_capability(capability)[:3]:
                        emit(
                            f"          {style(observation.evidence.location, 'underline')} "
                            f"{style(truncate(observation.evidence.excerpt, 60), 'dim')}"
                        )

    unused = {c for c in surface.unused if c.is_privileged}
    if unused:
        emit()
        emit(
            f"    {style('declared but not observed:', 'medium')} "
            + ", ".join(sorted(c.value for c in unused))
        )

    # -- external -----------------------------------------------------------
    heading("External resources")
    externals = sorted(
        {(r["host"], r["trust"], "; ".join(r.get("reasons", []))[:80]) for r in skill.externals if r.get("host")}
    )
    if not externals:
        emit(f"  {style('none referenced', 'dim')}")
    else:
        for host, trust, reason in externals:
            level = TrustLevel(trust)
            colour = {"pinned": "ok", "versioned": "low", "mutable": "medium", "unknown": "medium", "suspicious": "high"}[trust]
            emit(f"    {style('◈', 'dim')} {host:38} {style(level.label, colour)}")
            if reason:
                emit(f"        {style(truncate(reason, line_width - 12), 'dim')}")

    # -- dependencies -------------------------------------------------------
    if skill.dependencies:
        heading("Dependencies")
        for dependency in skill.dependencies[:20]:
            trust = dependency["trust"]
            colour = {"pinned": "ok", "versioned": "low", "mutable": "medium", "unknown": "medium", "suspicious": "high"}[trust]
            spec = f"{dependency['name']} {dependency.get('version', '')}".strip()
            emit(f"    {style('◇', 'dim')} {truncate(spec, 44):46} {style(trust, colour)}")
        if len(skill.dependencies) > 20:
            emit(f"    {style(f'… and {len(skill.dependencies) - 20} more', 'dim')}")

    # -- trust graph --------------------------------------------------------
    heading("Trust graph")
    for line in render_tree(graph):
        emit(f"    {line}")

    # -- findings -----------------------------------------------------------
    heading("Findings")
    actionable = [f for f in skill.findings if f.severity.rank <= Severity.LOW.rank]
    if not actionable:
        emit(f"  {style('no issues detected by the enabled checks', 'ok')}")
    else:
        for finding in actionable:
            emit(
                f"    {style.severity(finding.severity, finding.severity.value.rjust(8))}  "
                f"{style(finding.rule_id, 'bold')}  {finding.title}"
            )
            emit(f"              {style(finding.location, 'underline')}")

    # -- risk ---------------------------------------------------------------
    heading("Risk")
    for dimension in skill.risk.dimensions.values():
        marker = style.band(dimension.band, dimension.band.value.rjust(8))
        count = f"{dimension.count} finding(s)" if dimension.count else "clean"
        emit(f"    {dimension.label:28} {marker}   {style(count, 'dim')}")

    # -- coverage -----------------------------------------------------------
    heading("Analysis coverage")
    coverage = skill.coverage
    confidence_style = {"HIGH": "ok", "MEDIUM": "medium", "LOW": "high"}[coverage.confidence]
    emit(f"    Files analysed        {coverage.files_analyzed}/{coverage.files_discovered}")
    emit(f"    Nested archives       {coverage.archives_expanded}")
    emit(f"    Encoded regions       {coverage.encoded_regions}")
    emit(f"    Hidden Unicode        {'checked' if coverage.unicode_checked else 'not checked'}")
    emit(f"    Coverage confidence   {style(coverage.confidence, confidence_style)}")
    if coverage.gaps:
        emit()
        emit(f"    {style('Not analysed:', 'medium')}")
        for gap in coverage.gaps[: (None if verbose else 5)]:
            emit(f"      {gap['path']} {style('(' + gap['reason'] + ')', 'dim')}")
        if not verbose and len(coverage.gaps) > 5:
            emit(f"      {style(f'… and {len(coverage.gaps) - 5} more', 'dim')}")

    # -- verdict ------------------------------------------------------------
    heading("Verdict")
    emit(f"    {style.verdict(verdict, verdict.value)} — {verdict.summary}")
    for reason in skill.risk.rationale:
        for line in wrap(reason, line_width - 8, "      "):
            emit(style(line, "dim"))

    emit()
    emit(
        style(
            "  This is a static analysis. It reports what the enabled checks could observe;",
            "dim",
        )
    )
    emit(style("  it does not establish that the skill is safe to run.", "dim"))
    emit()
