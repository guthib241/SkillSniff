"""Command-line interface.

Exit codes are part of the contract, because the primary consumer is CI:

    0  no findings at or above the failure threshold
    1  findings at or above the failure threshold
    2  usage error, or nothing found to scan
    3  the tool itself failed

Exit code 1 means "the gate caught something". Exit code 3 means "the gate did
not run". Conflating those is how a broken scanner shows up as a passing build,
so they are kept distinct.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from skillsniff import __version__
from skillsniff.core.config import Config, discover, load_file
from skillsniff.core.errors import ConfigError, SkillSniffError, UsageError
from skillsniff.core.limits import Limits
from skillsniff.model.finding import Severity

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3

FORMATS = ("terminal", "json", "sarif", "markdown")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, help="path to a configuration file")
    parser.add_argument("--no-config", action="store_true", help="ignore any discovered config file")
    parser.add_argument(
        "--select", action="append", default=[], metavar="RULE",
        help="only run these rule ids or family prefixes (repeatable)",
    )
    parser.add_argument(
        "--ignore", action="append", default=[], metavar="RULE",
        help="suppress these rule ids or family prefixes (repeatable)",
    )
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB",
        help="skip paths matching this glob (repeatable)",
    )
    parser.add_argument(
        "--fail-on", metavar="SEVERITY",
        help="exit non-zero at this severity or above (default: high)",
    )
    parser.add_argument(
        "--min-severity", metavar="SEVERITY", help="hide findings below this severity",
    )
    parser.add_argument("--strict", action="store_true", help="fail on any finding, including low")
    parser.add_argument("--no-archives", action="store_true", help="do not inspect inside archives")
    parser.add_argument("--timeout", type=float, metavar="SECONDS", help="analysis time budget per skill")
    parser.add_argument("--max-file-size", type=int, metavar="BYTES", help="skip files larger than this")
    parser.add_argument("--follow-symlinks", action="store_true", help="follow symlinks inside the skill (off by default)")
    parser.add_argument("-q", "--quiet", action="store_true", help="findings only, no guidance")
    parser.add_argument("-v", "--verbose", action="store_true", help="show all evidence and coverage gaps")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--color", action="store_true", help="force ANSI colour")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillsniff",
        description="Security, trust, and capability analysis for AI agent skills.",
        epilog=(
            "A clean result means no issues were detected by the enabled checks. "
            "It is not a guarantee that a skill is safe."
        ),
    )
    parser.add_argument("--version", action="version", version=f"skillsniff {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = sub.add_parser("scan", help="analyse a skill or a directory of skills")
    scan.add_argument("path", nargs="?", default=".", type=Path)
    scan.add_argument("--format", choices=FORMATS, default="terminal")
    scan.add_argument("-o", "--output", type=Path, help="write the report to a file")
    _add_common(scan)
    scan.set_defaults(func=cmd_scan)

    inspect = sub.add_parser("inspect", help="produce a full trust report for one skill")
    inspect.add_argument("path", type=Path)
    inspect.add_argument("--format", choices=("terminal", "json"), default="terminal")
    inspect.add_argument("-o", "--output", type=Path)
    _add_common(inspect)
    inspect.set_defaults(func=cmd_inspect)

    rules = sub.add_parser("rules", help="list the rule catalogue")
    rules.add_argument("--family", help="restrict to one family, e.g. EXF")
    rules.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    rules.add_argument("--no-color", action="store_true")
    rules.add_argument("--color", action="store_true")
    rules.set_defaults(func=cmd_rules)

    explain = sub.add_parser("explain", help="explain a rule in full")
    explain.add_argument("rule_id")
    explain.add_argument("--format", choices=("terminal", "json"), default="terminal")
    explain.add_argument("--no-color", action="store_true")
    explain.add_argument("--color", action="store_true")
    explain.set_defaults(func=cmd_explain)

    lock = sub.add_parser("lock", help="write a lockfile recording the skill's current state")
    lock.add_argument("path", type=Path)
    lock.add_argument("-o", "--output", type=Path, help="lockfile path (default: <skill>/skillsniff.lock.json)")
    _add_common(lock)
    lock.set_defaults(func=cmd_lock)

    verify = sub.add_parser("verify", help="check a skill against its lockfile")
    verify.add_argument("path", type=Path)
    verify.add_argument("--lockfile", type=Path)
    verify.add_argument("--format", choices=("terminal", "json"), default="terminal")
    _add_common(verify)
    verify.set_defaults(func=cmd_verify)

    diff = sub.add_parser("diff", help="compare two versions of a skill")
    diff.add_argument("old", type=Path)
    diff.add_argument("new", type=Path)
    diff.add_argument("--format", choices=("terminal", "json", "markdown"), default="terminal")
    _add_common(diff)
    diff.set_defaults(func=cmd_diff)

    policy = sub.add_parser("policy", help="evaluate a skill against a policy document")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True, metavar="ACTION")
    check = policy_sub.add_parser("check", help="evaluate a skill against a policy")
    check.add_argument("path", type=Path)
    check.add_argument("--policy", type=Path, required=True)
    check.add_argument("--format", choices=("terminal", "json"), default="terminal")
    _add_common(check)
    check.set_defaults(func=cmd_policy_check)
    validate = policy_sub.add_parser("validate", help="check that a policy document is well-formed")
    validate.add_argument("policy", type=Path)
    validate.set_defaults(func=cmd_policy_validate)

    bench = sub.add_parser("benchmark", help="run the SkillSniffBench evaluation corpus")
    bench.add_argument("--corpus", type=Path, help="path to a corpus directory")
    bench.add_argument("--format", choices=("terminal", "json"), default="terminal")
    bench.add_argument("-o", "--output", type=Path)
    bench.add_argument("--no-color", action="store_true")
    bench.add_argument("--color", action="store_true")
    bench.set_defaults(func=cmd_benchmark)

    return parser


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------


def resolve_config(args: argparse.Namespace) -> Config:
    """Merge the config file with command-line flags. Flags always win."""
    if getattr(args, "config", None):
        config = load_file(args.config)
    elif getattr(args, "no_config", False):
        config = Config()
    else:
        target = getattr(args, "path", None) or getattr(args, "new", None) or Path(".")
        config = discover(Path(target))

    if getattr(args, "select", None):
        config.select = tuple(_split_all(args.select))
    if getattr(args, "ignore", None):
        config.ignore = tuple(config.ignore) + tuple(_split_all(args.ignore))
    if getattr(args, "exclude", None):
        config.exclude = tuple(config.exclude) + tuple(args.exclude)
    # Severity.parse raises ValueError, which is not a SkillSniffError and so
    # escaped the CLI's handler as a traceback. A mistyped flag must produce a
    # usage error, not a crash.
    if getattr(args, "fail_on", None):
        config.fail_on = _parse_severity(args.fail_on, "--fail-on")
    if getattr(args, "min_severity", None):
        config.min_severity = _parse_severity(args.min_severity, "--min-severity")
    if getattr(args, "strict", False):
        config.strict = True
        config.fail_on = Severity.LOW
    if getattr(args, "no_archives", False):
        config.expand_archives = False

    limits = config.limits
    changes: dict[str, Any] = {}
    if getattr(args, "timeout", None):
        changes["time_budget_seconds"] = args.timeout
    if getattr(args, "max_file_size", None):
        changes["max_file_bytes"] = args.max_file_size
    if getattr(args, "follow_symlinks", False):
        changes["follow_symlinks"] = True
    if changes:
        from dataclasses import fields as dataclass_fields

        current = {f.name: getattr(limits, f.name) for f in dataclass_fields(Limits)}
        config.limits = Limits(**{**current, **changes})

    return config


def _parse_severity(value: str, flag: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise UsageError(f"{flag}: {exc}") from exc


def _split_all(values: list[str]) -> list[str]:
    """Accept both --select EXF --select INJ and --select EXF,INJ."""
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def _color_enabled(args: argparse.Namespace, stream: Any) -> bool:
    from skillsniff.report.style import supports_color

    if getattr(args, "no_color", False):
        return False
    if getattr(args, "color", False):
        return True
    return supports_color(stream)


def _open_output(args: argparse.Namespace):
    """Return (stream, should_close). Writing to a file disables colour."""
    output = getattr(args, "output", None)
    if output:
        return output.open("w", encoding="utf-8"), True
    return sys.stdout, False


def _exit_code(result: Any, config: Config) -> int:
    threshold = config.fail_on
    if any(f.severity.rank <= threshold.rank for f in result.all_findings):
        return EXIT_FINDINGS
    return EXIT_OK


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    from skillsniff.engine import scan
    from skillsniff.report import json_report, markdown, sarif, terminal

    config = resolve_config(args)
    result = scan(args.path.resolve(), config)

    if not result.skills:
        for error in result.errors:
            print(f"skillsniff: {error}", file=sys.stderr)
        return EXIT_USAGE

    stream, should_close = _open_output(args)
    try:
        if args.format == "json":
            json_report.render(result, stream)
        elif args.format == "sarif":
            sarif.render(result, stream)
        elif args.format == "markdown":
            markdown.render(result, stream)
        else:
            terminal.render(
                result,
                stream,
                color=_color_enabled(args, stream),
                quiet=args.quiet,
                verbose=args.verbose,
                min_severity=config.min_severity,
            )
    finally:
        if should_close:
            stream.close()

    return _exit_code(result, config)


def cmd_inspect(args: argparse.Namespace) -> int:
    import json

    from skillsniff.analysis.context import build_context
    from skillsniff.analysis.graph import build_graph
    from skillsniff.core.limits import Budget
    from skillsniff.engine import analyze_skill, load_rules
    from skillsniff.model.skill import load_skill
    from skillsniff.report.trust import render

    config = resolve_config(args)
    path = args.path.resolve()

    budget = Budget(limits=config.limits)
    skill = load_skill(path, budget, excludes=config.exclude, expand_archives=config.expand_archives)
    if skill is None:
        print(f"skillsniff: no SKILL.md found at {path}", file=sys.stderr)
        return EXIT_USAGE

    load_rules()
    result, errors, _ = analyze_skill(skill, config, budget)
    context = build_context(skill, config, budget)
    graph = build_graph(context)

    stream, should_close = _open_output(args)
    try:
        if args.format == "json":
            payload = result.as_dict()
            payload["trust_graph"] = graph.as_dict()
            json.dump(payload, stream, indent=2)
            print(file=stream)
        else:
            render(
                result, context, graph, stream,
                color=_color_enabled(args, stream), verbose=args.verbose,
            )
    finally:
        if should_close:
            stream.close()

    for error in errors:
        print(f"skillsniff: {error}", file=sys.stderr)

    return EXIT_FINDINGS if any(
        f.severity.rank <= config.fail_on.rank for f in result.findings
    ) else EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    import json

    from skillsniff.engine import load_rules
    from skillsniff.report.style import Style, wrap
    from skillsniff.rules.base import Family, registry

    load_rules()
    metas = registry.all_meta()
    if args.family:
        try:
            family = Family(args.family.upper())
        except ValueError:
            valid = ", ".join(f.value for f in Family)
            print(f"skillsniff: unknown family {args.family!r}; valid: {valid}", file=sys.stderr)
            return EXIT_USAGE
        metas = [m for m in metas if m.family is family]

    if args.format == "json":
        json.dump(
            [
                {
                    "id": m.id, "title": m.title, "family": m.family.value,
                    "family_label": m.family.label, "severity": m.severity.value,
                    "confidence": m.confidence.value, "explanation": m.explanation,
                    "impact": m.impact, "remediation": m.remediation,
                    "limitations": m.limitations, "references": list(m.references),
                    "taxonomy": list(m.taxonomy), "experimental": m.experimental,
                    "security": m.family.is_security,
                }
                for m in metas
            ],
            sys.stdout, indent=2,
        )
        print()
        return EXIT_OK

    if args.format == "markdown":
        print("# SkillSniff rule catalogue\n")
        for family in sorted({m.family for m in metas}, key=lambda f: f.value):
            print(f"\n## {family.value} — {family.label}\n")
            print("| Rule | Severity | Confidence | Title |")
            print("| --- | --- | --- | --- |")
            for meta in (m for m in metas if m.family is family):
                print(f"| `{meta.id}` | {meta.severity.value} | {meta.confidence.value} | {meta.title} |")
        return EXIT_OK

    style = Style(_color_enabled(args, sys.stdout))
    current: Family | None = None
    for meta in metas:
        if meta.family is not current:
            current = meta.family
            marker = "" if current.is_security else style("  (not security)", "dim")
            print()
            print(f"  {style(current.value, 'bold')}  {current.label}{marker}")
            print(f"  {style('─' * 60, 'dim')}")
        print(
            f"    {style(meta.id, 'bold'):<20} {style.severity(meta.severity, meta.severity.value.rjust(8))}"
            f"  {style(meta.confidence.value.rjust(6), 'dim')}  {meta.title}"
        )
    print()
    print(f"  {len(metas)} rules. Run {style('skillsniff explain <RULE>', 'bold')} for full detail.")
    print()
    return EXIT_OK


def cmd_explain(args: argparse.Namespace) -> int:
    import json

    from skillsniff.engine import load_rules
    from skillsniff.report.style import Style, width, wrap
    from skillsniff.rules.base import registry

    load_rules()
    meta = registry.meta(args.rule_id)
    if meta is None:
        matches = [m.id for m in registry.all_meta() if m.id.startswith(args.rule_id.upper())]
        print(f"skillsniff: unknown rule {args.rule_id!r}", file=sys.stderr)
        if matches:
            print(f"  did you mean: {', '.join(matches[:8])}", file=sys.stderr)
        else:
            print("  run 'skillsniff rules' to list every rule", file=sys.stderr)
        return EXIT_USAGE

    if args.format == "json":
        json.dump(
            {
                "id": meta.id, "title": meta.title, "family": meta.family.value,
                "family_label": meta.family.label, "severity": meta.severity.value,
                "confidence": meta.confidence.value, "explanation": meta.explanation,
                "impact": meta.impact, "remediation": meta.remediation,
                "limitations": meta.limitations, "references": list(meta.references),
                "taxonomy": list(meta.taxonomy), "experimental": meta.experimental,
                "security": meta.family.is_security,
            },
            sys.stdout, indent=2,
        )
        print()
        return EXIT_OK

    style = Style(_color_enabled(args, sys.stdout))
    line_width = min(width(), 88)

    def section(title: str, body: str) -> None:
        if not body:
            return
        print()
        print(f"  {style(title, 'bold')}")
        for line in wrap(body, line_width - 4, "    "):
            print(line)

    print()
    print(f"  {style(meta.id, 'bold')}  {meta.title}")
    print(
        f"  {style(meta.family.value + ' · ' + meta.family.label, 'dim')}   "
        f"{style.severity(meta.severity)} · {meta.confidence.value} confidence"
        + ("" if meta.family.is_security else style("   (quality, not security)", "dim"))
        + (style("   [experimental]", "medium") if meta.experimental else "")
    )

    section("What it detects", meta.explanation)
    section("Why it matters", meta.impact)
    section("How to fix it", meta.remediation)
    section("What it cannot detect", meta.limitations or "Not documented for this rule.")

    if meta.taxonomy:
        section("Related taxonomy", ", ".join(meta.taxonomy))
    if meta.references:
        print()
        print(f"  {style('References', 'bold')}")
        for reference in meta.references:
            print(f"    {reference}")
    print()
    return EXIT_OK


def cmd_lock(args: argparse.Namespace) -> int:
    from skillsniff.provenance.lock import write_lock

    config = resolve_config(args)
    path = args.path.resolve()
    output = args.output or (path / "skillsniff.lock.json")
    try:
        lock = write_lock(path, output, config)
    except SkillSniffError as exc:
        print(f"skillsniff: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(f"skillsniff: wrote {output}")
    print(f"  skill        {lock['skill']['name']}")
    print(f"  files        {len(lock['files'])}")
    print(f"  content hash {lock['content_hash'][:32]}…")
    print(f"  capabilities {len(lock['capabilities'])}")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    import json

    from skillsniff.provenance.verify import verify

    config = resolve_config(args)
    path = args.path.resolve()
    lockfile = args.lockfile or (path / "skillsniff.lock.json")
    try:
        report = verify(path, lockfile, config)
    except SkillSniffError as exc:
        print(f"skillsniff: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.format == "json":
        json.dump(report.as_dict(), sys.stdout, indent=2)
        print()
    else:
        from skillsniff.report.style import Style

        style = Style(_color_enabled(args, sys.stdout))
        print()
        status = style("VERIFIED", "ok") if report.ok else style("CHANGED", "high")
        print(f"  {style(report.skill, 'bold')}  {status}")
        print(f"  {style('locked ' + report.locked_at, 'dim')}")
        print()
        for change in report.changes:
            colour = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}[change.severity]
            print(f"    {style(change.severity.rjust(8), colour)}  {change.kind:22} {change.detail}")
        if report.ok:
            print(f"    {style('no changes since the lockfile was written', 'dim')}")
        print()
    return EXIT_OK if report.ok else EXIT_FINDINGS


def cmd_diff(args: argparse.Namespace) -> int:
    import json

    from skillsniff.diff.compare import compare
    from skillsniff.report import diff_report

    config = resolve_config(args)
    try:
        result = compare(args.old.resolve(), args.new.resolve(), config)
    except SkillSniffError as exc:
        print(f"skillsniff: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.format == "json":
        json.dump(result.as_dict(), sys.stdout, indent=2)
        print()
    elif args.format == "markdown":
        diff_report.render_markdown(result, sys.stdout)
    else:
        diff_report.render_terminal(result, sys.stdout, color=_color_enabled(args, sys.stdout))

    return EXIT_FINDINGS if result.significant else EXIT_OK


def cmd_policy_check(args: argparse.Namespace) -> int:
    import json

    from skillsniff.engine import scan
    from skillsniff.policy.engine import evaluate, load_policy
    from skillsniff.report import policy_report

    config = resolve_config(args)
    try:
        policy = load_policy(args.policy)
    except (ConfigError, SkillSniffError) as exc:
        print(f"skillsniff: {exc}", file=sys.stderr)
        return EXIT_USAGE

    result = scan(args.path.resolve(), config)
    if not result.skills:
        for error in result.errors:
            print(f"skillsniff: {error}", file=sys.stderr)
        return EXIT_USAGE

    decisions = [evaluate(policy, skill) for skill in result.skills]

    if args.format == "json":
        json.dump(
            {
                "policy": policy.name,
                "decisions": [d.as_dict() for d in decisions],
                "allowed": all(d.allowed for d in decisions),
            },
            sys.stdout, indent=2,
        )
        print()
    else:
        policy_report.render(policy, decisions, sys.stdout, color=_color_enabled(args, sys.stdout))

    return EXIT_OK if all(d.allowed for d in decisions) else EXIT_FINDINGS


def cmd_policy_validate(args: argparse.Namespace) -> int:
    from skillsniff.policy.engine import load_policy

    try:
        policy = load_policy(args.policy)
    except (ConfigError, SkillSniffError) as exc:
        print(f"skillsniff: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(f"skillsniff: {args.policy} is valid")
    print(f"  name           {policy.name}")
    print(f"  max risk       {policy.max_risk.value if policy.max_risk else '(unset)'}")
    print(f"  deny           {len(policy.deny)} rule(s)")
    print(f"  require review {len(policy.require_approval)} rule(s)")
    return EXIT_OK


def cmd_benchmark(args: argparse.Namespace) -> int:
    import json

    from skillsniff.bench.runner import default_corpus_path, run_benchmark
    from skillsniff.report import bench_report

    corpus = args.corpus or default_corpus_path()
    if not corpus.exists():
        print(f"skillsniff: no corpus at {corpus}", file=sys.stderr)
        print("  the benchmark corpus ships with the source tree, not the wheel", file=sys.stderr)
        return EXIT_USAGE

    report = run_benchmark(corpus)
    stream, should_close = _open_output(args)
    try:
        if args.format == "json":
            json.dump(report.as_dict(), stream, indent=2)
            print(file=stream)
        else:
            bench_report.render(report, stream, color=_color_enabled(args, stream))
    finally:
        if should_close:
            stream.close()
    return EXIT_OK


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (UsageError, ConfigError) as exc:
        print(f"skillsniff: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except SkillSniffError as exc:
        print(f"skillsniff: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        # `skillsniff scan | head` is a normal thing to do.
        return EXIT_OK
    except KeyboardInterrupt:
        print("skillsniff: interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
