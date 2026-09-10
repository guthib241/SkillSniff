"""Rendering for ``skillsniff diff``."""

from __future__ import annotations

import sys
from typing import TextIO

from skillsniff.diff.compare import DiffResult, SetDelta
from skillsniff.report.style import Style, truncate, width


def render_terminal(diff: DiffResult, stream: TextIO | None = None, *, color: bool = True) -> None:
    out = stream or sys.stdout
    style = Style(color)
    line_width = width()

    def emit(text: str = "") -> None:
        print(text, file=out)

    emit()
    label = diff.new_name
    versions = (
        f"{diff.old_version or 'old'} → {diff.new_version or 'new'}"
        if diff.old_version or diff.new_version
        else "old → new"
    )
    emit(f"  {style(label, 'bold')}  {style(versions, 'dim')}")
    emit()

    _section(emit, style, diff.capabilities, privileged=set(diff.privileged_added))
    _section(emit, style, diff.declared_tools)
    _section(emit, style, diff.externals)
    _section(emit, style, diff.dependencies)
    _section(emit, style, diff.findings)

    if diff.files.changed or diff.files_modified:
        emit(f"  {style('files', 'bold')}")
        for path in diff.files.added:
            emit(f"    {style('+', 'ok')} {path}")
        for path in diff.files.removed:
            emit(f"    {style('-', 'dim')} {path}")
        for path in diff.files_modified:
            emit(f"    {style('~', 'medium')} {path}")
        emit()

    emit(f"  {style('description', 'bold')}")
    if diff.description_changed:
        emit(f"    {style('-', 'dim')} {truncate(diff.old_description, line_width - 8)}")
        emit(f"    {style('+', 'ok')} {truncate(diff.new_description, line_width - 8)}")
    else:
        emit(f"    {style('unchanged', 'dim')}")
    emit()

    emit(style("  " + "─" * (line_width - 4), "dim"))
    emit(
        f"  verdict: {style.verdict(diff.old_verdict, diff.old_verdict.value)} → "
        f"{style.verdict(diff.new_verdict, diff.new_verdict.value)}"
    )

    if diff.undeclared_behaviour_change:
        emit()
        emit(f"  {style('NEW BEHAVIOUR IS NOT DECLARED', 'critical')}")
        emit(
            style(
                f"    the skill gained {', '.join(diff.privileged_added)} while its description "
                "and declared tools stayed the same",
                "dim",
            )
        )
    elif diff.verdict_worsened:
        emit()
        emit(f"  {style('RISK INCREASED', 'high')}")
    elif not diff.significant:
        emit()
        emit(f"  {style('no behavioural change detected', 'ok')}")
    emit()


def _section(emit, style: Style, delta: SetDelta, privileged: set[str] | None = None) -> None:
    if not delta.changed:
        return
    privileged = privileged or set()
    emit(f"  {style(delta.label, 'bold')}")
    for item in delta.added:
        marker = style("+", "critical" if item in privileged else "ok")
        suffix = style("  (privileged)", "critical") if item in privileged else ""
        emit(f"    {marker} {item}{suffix}")
    for item in delta.removed:
        emit(f"    {style('-', 'dim')} {item}")
    emit()


def render_markdown(diff: DiffResult, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout

    def emit(text: str = "") -> None:
        print(text, file=out)

    headline = (
        "🛑 New behaviour is not declared"
        if diff.undeclared_behaviour_change
        else ("⚠️ Risk increased" if diff.verdict_worsened else ("Capability surface changed" if diff.significant else "✅ No behavioural change"))
    )
    emit(f"## SkillSniff diff: {headline}")
    emit()
    emit(f"`{diff.old_name}` → `{diff.new_name}` · verdict **{diff.old_verdict.value} → {diff.new_verdict.value}**")
    emit()

    for delta in (diff.capabilities, diff.declared_tools, diff.externals, diff.dependencies, diff.findings):
        if not delta.changed:
            continue
        emit(f"**{delta.label.capitalize()}**")
        emit()
        for item in delta.added:
            flag = " ⚠️ privileged" if item in diff.privileged_added else ""
            emit(f"- `+ {item}`{flag}")
        for item in delta.removed:
            emit(f"- `- {item}`")
        emit()

    if diff.description_changed:
        emit("**Description changed**")
        emit()
        emit(f"- before: {diff.old_description}")
        emit(f"- after: {diff.new_description}")
        emit()
    elif diff.privileged_added:
        emit("> **Description unchanged.** The skill gained "
             f"{', '.join(f'`{c}`' for c in diff.privileged_added)} "
             "without any change to what it claims to do.")
        emit()

    emit("---")
    emit("<sub>SkillSniff compares behaviour, not just text. A clean diff is not a safety guarantee.</sub>")
