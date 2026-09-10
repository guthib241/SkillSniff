"""Pre-commit entry point.

pre-commit passes the files that changed. A skill is a *directory*, and any file
inside it can change what the analysis concludes — a new script, an edited
reference document, a modified dependency manifest — so this resolves each
changed path up to its owning skill and scans those skills whole.

Scanning whole skills rather than individual files is not an optimisation, it is
correctness: capability mismatch, the trust graph and the compound-risk rules are
all properties of a skill, and none of them can be evaluated from one file.
"""

from __future__ import annotations

import sys
from pathlib import Path

from skillsniff.cli import EXIT_OK, EXIT_USAGE, _parse_severity
from skillsniff.core.config import discover
from skillsniff.core.errors import SkillSniffError
from skillsniff.model.skill import find_entry
from skillsniff.report.style import supports_color

#: How far up to walk looking for a SKILL.md. Deep enough for
#: `skills/x/references/nested/file.md`, shallow enough not to escape a monorepo
#: package and start scanning a sibling.
MAX_ASCENT = 6


def owning_skill(path: Path, root: Path) -> Path | None:
    """The skill directory containing ``path``, or None if there is not one."""
    candidate = path if path.is_dir() else path.parent
    for _ in range(MAX_ASCENT):
        if find_entry(candidate) is not None:
            return candidate
        if candidate == root or candidate.parent == candidate:
            return None
        candidate = candidate.parent
    return None


def resolve_skills(paths: list[str], root: Path) -> list[Path]:
    """Map changed files to the distinct skill directories that own them."""
    found: list[Path] = []
    seen: set[Path] = set()
    for raw in paths:
        candidate = Path(raw)
        if not candidate.exists():
            continue  # deleted in this commit
        skill = owning_skill(candidate.resolve(), root)
        if skill is not None and skill not in seen:
            seen.add(skill)
            found.append(skill)
    return found


def main(argv: list[str] | None = None) -> int:
    from skillsniff.engine import scan
    from skillsniff.report import terminal

    argv = list(sys.argv[1:] if argv is None else argv)

    # Anything before a `--` is an option for us; the rest are filenames.
    severity = "high"
    files: list[str] = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--fail-on" and index + 1 < len(argv):
            severity = argv[index + 1]
            index += 2
            continue
        if argument.startswith("--fail-on="):
            severity = argument.split("=", 1)[1]
            index += 1
            continue
        files.append(argument)
        index += 1

    root = Path.cwd().resolve()
    skills = resolve_skills(files, root)
    if not skills:
        # No changed file belongs to a skill. Nothing to say.
        return EXIT_OK

    try:
        config = discover(skills[0])
        config.fail_on = _parse_severity(severity, "--fail-on")
    except SkillSniffError as exc:
        print(f"skillsniff: {exc}", file=sys.stderr)
        return EXIT_USAGE

    failed = False
    for skill in skills:
        result = scan(skill, config)
        if not result.skills:
            continue
        terminal.render(
            result,
            color=supports_color(sys.stdout),
            quiet=True,
            min_severity=config.min_severity,
            show_capabilities=False,
        )
        if any(f.severity.rank <= config.fail_on.rank for f in result.all_findings):
            failed = True

    if failed:
        print(
            "skillsniff: run 'skillsniff inspect <skill>' for the full trust report, or "
            "'skillsniff explain <RULE>' for any finding above.",
            file=sys.stderr,
        )
    return 1 if failed else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
