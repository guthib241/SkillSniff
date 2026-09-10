"""Semantic comparison of two skill versions.

A textual diff tells a reviewer that 40 lines changed. It does not tell them
that the skill can now reach the network. This produces the second answer.

The output is shaped for pull-request review, so the headline is the *behavioural*
delta — capabilities, external references, dependencies, declared tools — and the
single most important signal it can emit is that behaviour changed while the
stated purpose did not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillsniff.core.config import Config
from skillsniff.core.errors import UsageError
from skillsniff.core.limits import Budget
from skillsniff.model.capability import Capability
from skillsniff.model.result import SkillResult, Verdict
from skillsniff.model.skill import load_skill


@dataclass
class SetDelta:
    """Added and removed members of some set, with the label for reporting."""

    label: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)

    def as_dict(self) -> dict[str, Any]:
        return {"label": self.label, "added": self.added, "removed": self.removed}


@dataclass
class DiffResult:
    old_name: str
    new_name: str
    old_version: str = ""
    new_version: str = ""
    capabilities: SetDelta = field(default_factory=lambda: SetDelta("capabilities"))
    privileged_added: list[str] = field(default_factory=list)
    declared_tools: SetDelta = field(default_factory=lambda: SetDelta("declared tools"))
    externals: SetDelta = field(default_factory=lambda: SetDelta("external hosts"))
    dependencies: SetDelta = field(default_factory=lambda: SetDelta("dependencies"))
    files: SetDelta = field(default_factory=lambda: SetDelta("files"))
    files_modified: list[str] = field(default_factory=list)
    findings: SetDelta = field(default_factory=lambda: SetDelta("findings"))
    description_changed: bool = False
    old_description: str = ""
    new_description: str = ""
    old_verdict: Verdict = Verdict.CLEAR
    new_verdict: Verdict = Verdict.CLEAR

    @property
    def verdict_worsened(self) -> bool:
        return self.new_verdict.rank < self.old_verdict.rank

    @property
    def undeclared_behaviour_change(self) -> bool:
        """New privileged capability with no corresponding change to the claim.

        This is the finding that makes the command worth running in a pull
        request: the skill can do more than it could, and nothing a reviewer
        reads in the description or the tool list says so.
        """
        return bool(self.privileged_added) and not (
            self.description_changed or self.declared_tools.added
        )

    @property
    def significant(self) -> bool:
        return bool(
            self.privileged_added
            or self.verdict_worsened
            or self.externals.added
            or self.findings.added
            or self.declared_tools.added
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "old": {"name": self.old_name, "version": self.old_version, "verdict": self.old_verdict.value},
            "new": {"name": self.new_name, "version": self.new_version, "verdict": self.new_verdict.value},
            "capabilities": self.capabilities.as_dict(),
            "privileged_added": self.privileged_added,
            "declared_tools": self.declared_tools.as_dict(),
            "external_hosts": self.externals.as_dict(),
            "dependencies": self.dependencies.as_dict(),
            "files": {**self.files.as_dict(), "modified": self.files_modified},
            "findings": self.findings.as_dict(),
            "description_changed": self.description_changed,
            "verdict_worsened": self.verdict_worsened,
            "undeclared_behaviour_change": self.undeclared_behaviour_change,
            "significant": self.significant,
        }


def _analyse(path: Path, config: Config) -> tuple[SkillResult, Any, Any]:
    from skillsniff.analysis.context import build_context
    from skillsniff.engine import analyze_skill, load_rules

    budget = Budget(limits=config.limits)
    skill = load_skill(path, budget, excludes=config.exclude, expand_archives=config.expand_archives)
    if skill is None:
        raise UsageError(f"no SKILL.md found at {path}")
    load_rules()
    result, _errors, _ = analyze_skill(skill, config, budget)
    context = build_context(skill, config, budget)
    return result, context, skill


def _delta(label: str, before: set[str], after: set[str]) -> SetDelta:
    return SetDelta(label=label, added=sorted(after - before), removed=sorted(before - after))


def compare(old_path: Path, new_path: Path, config: Config | None = None) -> DiffResult:
    """Compare the skill at ``old_path`` with the skill at ``new_path``."""
    config = config or Config()
    old_result, old_context, old_skill = _analyse(old_path, config)
    new_result, new_context, new_skill = _analyse(new_path, config)

    old_caps = {c.value for c in old_context.capabilities.actual}
    new_caps = {c.value for c in new_context.capabilities.actual}

    diff = DiffResult(
        old_name=old_skill.dir_name,
        new_name=new_skill.dir_name,
        old_version=old_skill.version,
        new_version=new_skill.version,
        capabilities=_delta("capabilities", old_caps, new_caps),
        declared_tools=_delta("declared tools", set(old_skill.declared_tools), set(new_skill.declared_tools)),
        externals=_delta(
            "external hosts",
            {r.host for r in old_context.externals if r.host},
            {r.host for r in new_context.externals if r.host},
        ),
        dependencies=_delta(
            "dependencies",
            {f"{d.name}{d.version_spec}" for d in old_context.dependencies},
            {f"{d.name}{d.version_spec}" for d in new_context.dependencies},
        ),
        findings=_delta(
            "findings",
            {f.rule_id for f in old_result.findings},
            {f.rule_id for f in new_result.findings},
        ),
        description_changed=old_skill.description != new_skill.description,
        old_description=old_skill.description,
        new_description=new_skill.description,
        old_verdict=old_result.risk.verdict,
        new_verdict=new_result.risk.verdict,
    )

    diff.privileged_added = [
        value for value in diff.capabilities.added if _is_privileged(value)
    ]

    old_files = {f.relpath: f.sha256 for f in old_skill.files if not f.container}
    new_files = {f.relpath: f.sha256 for f in new_skill.files if not f.container}
    diff.files = _delta("files", set(old_files), set(new_files))
    diff.files_modified = sorted(
        p for p in set(old_files) & set(new_files) if old_files[p] != new_files[p]
    )

    return diff


def _is_privileged(value: str) -> bool:
    try:
        return Capability(value).is_privileged
    except ValueError:
        return False
