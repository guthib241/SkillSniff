"""Scan orchestration.

Loads skills, builds their analysis context once, runs every enabled rule
against it, then assembles the multi-dimensional result.

Rule isolation is deliberate: a rule that raises is recorded as an error and the
scan continues. A crash in one heuristic must never suppress the findings of the
other eighty-six, because the failure mode of "scanner crashed, CI went green"
is indistinguishable from "scanner passed".
"""

from __future__ import annotations

import importlib
import traceback
from pathlib import Path

from skillsniff import __version__
from skillsniff.analysis.context import AnalysisContext, build_context
from skillsniff.core.config import Config
from skillsniff.core.limits import Budget
from skillsniff.model.finding import Finding, deduplicate
from skillsniff.model.result import Coverage, ScanResult, SkillResult, assess
from skillsniff.model.skill import Skill, discover_skills, load_skill
from skillsniff.rules.base import registry

#: Importing these modules is what populates the registry.
RULE_MODULES = (
    "skillsniff.rules.spec",
    "skillsniff.rules.quality",
    "skillsniff.rules.injection",
    "skillsniff.rules.obfuscation",
    "skillsniff.rules.execution",
    "skillsniff.rules.secrets",
    "skillsniff.rules.supply",
    "skillsniff.rules.persistence",
    "skillsniff.rules.capability",
    "skillsniff.rules.compound",
)

_loaded = False


def load_rules() -> None:
    """Import every rule module exactly once."""
    global _loaded
    if _loaded:
        return
    for module in RULE_MODULES:
        importlib.import_module(module)
    _loaded = True


def run_rules(context: AnalysisContext) -> tuple[list[Finding], list[str], int]:
    """Run every enabled rule against ``context``.

    Returns (findings, errors, rules_run).
    """
    load_rules()
    findings: list[Finding] = []
    errors: list[str] = []
    executed = 0

    # A single callable may implement several rule ids, so count the ids that
    # were actually eligible rather than the number of functions invoked —
    # "44 rules" when 87 are enabled is a misleading thing to print.
    executed = sum(1 for rule_id in registry.implemented_ids() if context.config.is_enabled(rule_id))

    for rule_id, rule in registry.callables().items():
        if not any(
            context.config.is_enabled(candidate)
            for candidate, func in registry._rules.items()
            if func is rule
        ):
            continue
        if context.budget.time_exhausted():
            errors.append(f"time budget exhausted before rule {rule_id}")
            break
        try:
            produced = list(rule(context))
        except Exception as exc:
            errors.append(f"rule {rule_id} raised {type(exc).__name__}: {exc}")
            if context.config.strict:
                errors.append(traceback.format_exc(limit=3))
            continue
        # A rule may implement several ids; filter its output by what is enabled.
        findings.extend(f for f in produced if context.config.is_enabled(f.rule_id))

    return deduplicate(findings), errors, executed


def analyze_skill(skill: Skill, config: Config, budget: Budget) -> tuple[SkillResult, list[str], int]:
    """Build the context, run the rules, and assemble one skill's result."""
    context = build_context(skill, config, budget)
    findings, errors, executed = run_rules(context)

    coverage = Coverage.from_budget(budget)
    result = SkillResult(
        name=skill.dir_name,
        path=str(skill.root),
        findings=findings,
        capabilities=context.capabilities,
        coverage=coverage,
        risk=assess(findings, coverage),
        externals=[r.as_dict() for r in context.externals],
        dependencies=[d.as_dict() for d in context.dependencies],
        description=skill.description,
        version=skill.version,
        declared_tools=skill.declared_tools,
        file_count=len(skill.all_files),
        total_bytes=skill.total_bytes,
    )
    return result, errors, executed


def scan(path: Path, config: Config | None = None) -> ScanResult:
    """Scan a skill directory, or a directory containing skills."""
    config = config or Config()
    result = ScanResult(tool_version=__version__, scanned_path=str(path))

    if not path.exists():
        result.errors.append(f"no such path: {path}")
        return result

    # Each skill gets its own budget so one oversized skill cannot starve the
    # analysis of the ones after it.
    probe_budget = Budget(limits=config.limits)
    if (path / "SKILL.md").exists() or (path / "skill.md").exists():
        skill = load_skill(
            path, probe_budget, excludes=config.exclude, expand_archives=config.expand_archives
        )
        skills = [skill] if skill else []
        budgets = [probe_budget]
    else:
        skills = discover_skills(
            path, Budget(limits=config.limits), excludes=config.exclude, expand_archives=False
        )
        # Reload each skill under its own budget, now that we know where they are.
        reloaded: list[Skill] = []
        budgets = []
        for found in skills:
            budget = Budget(limits=config.limits)
            fresh = load_skill(
                found.root,
                budget,
                excludes=config.exclude,
                expand_archives=config.expand_archives,
            )
            if fresh is not None:
                reloaded.append(fresh)
                budgets.append(budget)
        skills = reloaded

    if not skills:
        result.errors.append(f"no SKILL.md found under {path}")
        return result

    rules_run = 0
    for skill, budget in zip(skills, budgets, strict=True):
        skill_result, errors, executed = analyze_skill(skill, config, budget)
        result.skills.append(skill_result)
        result.errors.extend(errors)
        rules_run = max(rules_run, executed)

    result.rules_run = rules_run
    result.skills.sort(key=lambda s: (s.risk.verdict.rank, s.name))
    return result
