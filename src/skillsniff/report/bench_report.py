"""Rendering for ``skillsniff benchmark``."""

from __future__ import annotations

import sys
from typing import TextIO

from skillsniff.bench.runner import BenchmarkReport, Metrics
from skillsniff.report.style import Style, truncate, width


def render(report: BenchmarkReport, stream: TextIO | None = None, *, color: bool = True) -> None:
    out = stream or sys.stdout
    style = Style(color)
    line_width = width()

    def emit(text: str = "") -> None:
        print(text, file=out)

    emit()
    emit(f"  {style('SkillSniffBench', 'bold')} {style('· ' + report.corpus, 'dim')}")
    emit(f"  {style(f'skillsniff {report.tool_version}', 'dim')}")
    emit()

    _metrics_block(emit, style, "overall", report.overall)

    if len(report.by_source) > 1:
        emit(f"  {style('by source', 'bold')}")
        emit(
            f"    {'source':<16}{'cases':>7}{'precision':>11}{'recall':>9}{'F1':>8}"
            f"{'FPR':>8}"
        )
        for source, metrics in sorted(report.by_source.items()):
            emit(
                f"    {source:<16}{metrics.total:>7}{metrics.precision:>11.3f}"
                f"{metrics.recall:>9.3f}{metrics.f1:>8.3f}{metrics.false_positive_rate:>8.3f}"
            )
        emit()

    emit(f"  {style('by category', 'bold')}")
    emit(f"    {'category':<28}{'cases':>7}{'TP':>5}{'FP':>5}{'TN':>5}{'FN':>5}")
    for category, metrics in sorted(report.by_category.items()):
        emit(
            f"    {truncate(category, 27):<28}{metrics.total:>7}{metrics.true_positive:>5}"
            f"{metrics.false_positive:>5}{metrics.true_negative:>5}{metrics.false_negative:>5}"
        )
    emit()

    failures = report.expectation_failures
    if failures:
        emit(f"  {style('failures', 'high')}  {len(failures)} case(s) did not behave as expected")
        for result in failures:
            emit(f"    {style(result.case.name, 'bold')}  [{result.case.label}] → {result.verdict.value}")
            if result.error:
                emit(f"      {style('error: ' + result.error, 'high')}")
            if result.missing_expected:
                emit(f"      {style('expected but did not fire:', 'high')} {', '.join(result.missing_expected)}")
            if result.forbidden_fired:
                emit(f"      {style('fired but must not:', 'high')} {', '.join(result.forbidden_fired)}")
            if result.outcome == "false_negative":
                emit(f"      {style('missed a malicious case', 'high')}")
            if result.outcome == "false_positive":
                emit(
                    f"      {style('flagged a benign case:', 'high')} "
                    f"{', '.join(sorted(result.rules_fired)[:6])}"
                )
        emit()

    emit(style("  " + "─" * (line_width - 4), "dim"))
    emit(
        f"  {len(report.results)} cases in {report.total_elapsed_ms:.0f} ms "
        f"({style('median ' + f'{report.median_ms:.1f} ms/skill', 'dim')})"
    )
    status = (
        style("all expectations met", "ok")
        if not failures
        else style(f"{len(failures)} expectation failure(s)", "high")
    )
    emit(f"  {status}")

    internal_only = set(report.by_source) <= {"internal"}
    if internal_only:
        emit()
        emit(f"  {style('Interpret these numbers narrowly.', 'medium')}")
        for line in (
            "Every case in this corpus was written by this project, alongside the rules "
            "it exercises. The result therefore measures whether SkillSniff does what its "
            "authors intended on inputs its authors chose — it is a regression suite, not "
            "evidence of generalisation.",
            "Precision and recall against skills in the wild are unmeasured. Treat a "
            "source-disjoint evaluation against an external corpus as the number that "
            "would actually mean something.",
        ):
            for wrapped in _wrap(line, line_width - 6, "    "):
                emit(style(wrapped, "dim"))
    emit()


def _wrap(text: str, limit: int, indent: str) -> list[str]:
    from skillsniff.report.style import wrap

    return wrap(text, limit, indent)


def _metrics_block(emit, style: Style, label: str, metrics: Metrics) -> None:
    emit(f"  {style(label, 'bold')}")
    emit(
        f"    precision {style(f'{metrics.precision:.3f}', 'bold')}   "
        f"recall {style(f'{metrics.recall:.3f}', 'bold')}   "
        f"F1 {style(f'{metrics.f1:.3f}', 'bold')}"
    )
    emit(
        f"    false-positive rate {metrics.false_positive_rate:.3f}   "
        f"false-negative rate {metrics.false_negative_rate:.3f}"
    )
    emit(
        f"    TP {metrics.true_positive}  FP {metrics.false_positive}  "
        f"TN {metrics.true_negative}  FN {metrics.false_negative}   "
        f"({metrics.total} cases)"
    )
    emit()
