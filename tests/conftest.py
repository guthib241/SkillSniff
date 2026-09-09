"""Shared fixtures.

``build_skill`` is the workhorse: it writes a complete, spec-valid skill to a
temporary directory so a test can express only the thing it is testing. Tests
that start from an already-clean skill are what make a false-positive test
meaningful, because the only difference between the clean case and the test case
is the one line under examination.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from skillsniff.core.config import Config
from skillsniff.core.limits import Budget
from skillsniff.engine import load_rules, scan
from skillsniff.model.finding import Severity

CLEAN_FRONTMATTER = """---
name: {name}
description: Reviews a document and reports findings as a table. Use when the user asks for a review of a document or file.
license: MIT
---
"""

CLEAN_BODY = """
# Sample skill

## Rules

Always read the document in full before reporting. Do not report on a section
you have not read; this step must not be skipped.

## Steps

1. Read the document.
2. Identify the sections.
3. Check each section against the criteria.
4. Verify that every finding cites a location.
5. Write the report.

Track progress with a checklist:

- [ ] Document read
- [ ] Sections identified

## Guardrails

Do not report a finding you cannot cite. If the criteria are unclear, stop and
ask the user rather than guessing.

## Caveats

A common pitfall is reporting on the summary instead of the body.

## Output

```
| Section | Finding |
| ------- | ------- |
```

**Warning:** never edit the document while reviewing it.
"""


def write_skill(
    root: Path,
    name: str = "sample-review",
    *,
    body: str | None = None,
    frontmatter: str | None = None,
    files: dict[str, str | bytes] | None = None,
) -> Path:
    """Write a skill directory and return its path."""
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    header = frontmatter if frontmatter is not None else CLEAN_FRONTMATTER.format(name=name)
    (directory / "SKILL.md").write_text(
        header + (body if body is not None else CLEAN_BODY), encoding="utf-8"
    )
    for relative, content in (files or {}).items():
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return directory


@pytest.fixture(scope="session", autouse=True)
def _rules_loaded() -> None:
    load_rules()


@pytest.fixture
def build_skill(tmp_path: Path):
    """Factory returning the path of a freshly written skill."""

    def _build(**kwargs) -> Path:
        return write_skill(tmp_path, **kwargs)

    return _build


@pytest.fixture
def scan_skill(build_skill):
    """Build a skill and return its :class:`SkillResult`."""

    def _scan(config: Config | None = None, **kwargs):
        path = build_skill(**kwargs)
        result = scan(path, config or Config())
        assert result.skills, f"no skill discovered at {path}"
        return result.skills[0]

    return _scan


@pytest.fixture
def rule_ids(scan_skill):
    """Build a skill and return the set of rule ids that fired."""

    def _ids(**kwargs) -> set[str]:
        return {f.rule_id for f in scan_skill(**kwargs).findings}

    return _ids


@pytest.fixture
def actionable_rule_ids(scan_skill):
    """Rule ids that fired at MEDIUM severity or above."""

    def _ids(**kwargs) -> set[str]:
        return {
            f.rule_id
            for f in scan_skill(**kwargs).findings
            if f.severity.rank <= Severity.MEDIUM.rank
        }

    return _ids


@pytest.fixture
def budget() -> Budget:
    return Budget()
