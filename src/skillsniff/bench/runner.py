"""SkillSniffBench — the evaluation harness.

Every case in the corpus is a real skill directory plus a ``_bench.toml``
declaring what it is and what should happen. The runner scans each one and
scores two things:

*Detection.* Does a malicious case reach a verdict of BLOCK or REVIEW, and does
a benign case stay at CLEAR or CAUTION? This is the metric that matters for a
gate, and it is what precision, recall and F1 are computed over.

*Rule expectations.* Did the specific rules that ought to fire, fire — and did
the rules that must not fire, stay quiet? A case can be detected for the wrong
reason, and this is what catches that.

``forbid_rules`` means "must not produce an *actionable* finding", defined as
MEDIUM severity or above. This matters because several rules deliberately
downgrade rather than suppress when content is framed as documentation: a
security skill that shows ``curl … | bash`` as an attack example still gets a
LOW/low-confidence note recording that the pattern is present, because silently
dropping evidence is worse than recording it quietly. That note must not gate a
build, and MEDIUM is where gating begins. Use ``forbid_rules_entirely`` for the
stricter contract that a rule must not fire at any severity.

The corpus records the ``source`` of every case. Cases written for this project
are marked ``internal``; anything derived from a public dataset is marked
``external`` and reported separately, because a tool evaluated only on tests its
own authors wrote has not been evaluated.
"""

from __future__ import annotations

import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillsniff.core.config import Config
from skillsniff.core.errors import UsageError
from skillsniff.model.finding import Severity
from skillsniff.model.result import Verdict

BENCH_FILE = "_bench.toml"

#: Verdicts that count as "this tool flagged the skill".
FLAGGED = {Verdict.BLOCK, Verdict.REVIEW}


@dataclass
class Case:
    name: str
    path: Path
    label: str              # "malicious" | "benign"
    category: str = "uncategorised"
    description: str = ""
    source: str = "internal"
    expect_rules: tuple[str, ...] = ()
    #: Must not produce a finding at MEDIUM severity or above.
    forbid_rules: tuple[str, ...] = ()
    #: Must not produce a finding at any severity.
    forbid_rules_entirely: tuple[str, ...] = ()
    expect_verdict: str = ""

    @property
    def is_malicious(self) -> bool:
        return self.label == "malicious"


@dataclass
class CaseResult:
    case: Case
    verdict: Verdict
    flagged: bool
    rules_fired: set[str] = field(default_factory=set)
    #: Rules that produced a finding at MEDIUM severity or above.
    rules_actionable: set[str] = field(default_factory=set)
    missing_expected: list[str] = field(default_factory=list)
    forbidden_fired: list[str] = field(default_factory=list)
    verdict_mismatch: bool = False
    elapsed_ms: float = 0.0
    error: str = ""

    @property
    def correct(self) -> bool:
        """Detection is correct and no expectation was violated."""
        detection_ok = self.flagged == self.case.is_malicious
        return (
            detection_ok
            and not self.missing_expected
            and not self.forbidden_fired
            and not self.verdict_mismatch
            and not self.error
        )

    @property
    def outcome(self) -> str:
        if self.error:
            return "error"
        if self.case.is_malicious:
            return "true_positive" if self.flagged else "false_negative"
        return "false_positive" if self.flagged else "true_negative"

    def as_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.name,
            "label": self.case.label,
            "category": self.case.category,
            "source": self.case.source,
            "verdict": self.verdict.value,
            "outcome": self.outcome,
            "correct": self.correct,
            "rules_fired": sorted(self.rules_fired),
            "rules_actionable": sorted(self.rules_actionable),
            "missing_expected": self.missing_expected,
            "forbidden_fired": self.forbidden_fired,
            "elapsed_ms": round(self.elapsed_ms, 2),
            **({"error": self.error} if self.error else {}),
        }


@dataclass
class Metrics:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def total(self) -> int:
        return self.true_positive + self.false_positive + self.true_negative + self.false_negative

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else 0.0

    @property
    def false_negative_rate(self) -> float:
        denominator = self.false_negative + self.true_positive
        return self.false_negative / denominator if denominator else 0.0

    def add(self, outcome: str) -> None:
        mapping = {
            "true_positive": "true_positive",
            "false_positive": "false_positive",
            "true_negative": "true_negative",
            "false_negative": "false_negative",
        }
        attribute = mapping.get(outcome)
        if attribute:
            setattr(self, attribute, getattr(self, attribute) + 1)

    def as_dict(self) -> dict[str, Any]:
        return {
            "cases": self.total,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
        }


@dataclass
class BenchmarkReport:
    corpus: str
    results: list[CaseResult] = field(default_factory=list)
    overall: Metrics = field(default_factory=Metrics)
    by_source: dict[str, Metrics] = field(default_factory=dict)
    by_category: dict[str, Metrics] = field(default_factory=dict)
    total_elapsed_ms: float = 0.0
    tool_version: str = ""

    @property
    def expectation_failures(self) -> list[CaseResult]:
        return [r for r in self.results if not r.correct]

    @property
    def median_ms(self) -> float:
        if not self.results:
            return 0.0
        values = sorted(r.elapsed_ms for r in self.results)
        return values[len(values) // 2]

    def as_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "tool_version": self.tool_version,
            "cases": len(self.results),
            "overall": self.overall.as_dict(),
            "by_source": {k: v.as_dict() for k, v in sorted(self.by_source.items())},
            "by_category": {k: v.as_dict() for k, v in sorted(self.by_category.items())},
            "timing": {
                "total_ms": round(self.total_elapsed_ms, 2),
                "median_ms": round(self.median_ms, 2),
                "mean_ms": round(self.total_elapsed_ms / len(self.results), 2) if self.results else 0.0,
            },
            "expectation_failures": [r.as_dict() for r in self.expectation_failures],
            "results": [r.as_dict() for r in self.results],
        }


def default_corpus_path() -> Path:
    return Path(__file__).parent / "corpus"


def load_cases(corpus: Path) -> list[Case]:
    """Discover every ``_bench.toml`` under ``corpus``."""
    cases: list[Case] = []
    for manifest in sorted(corpus.rglob(BENCH_FILE)):
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise UsageError(f"{manifest}: {exc}") from exc

        label = str(data.get("label", "")).lower()
        if label not in ("malicious", "benign"):
            raise UsageError(f"{manifest}: 'label' must be 'malicious' or 'benign'")

        cases.append(
            Case(
                name=data.get("name") or manifest.parent.name,
                path=manifest.parent,
                label=label,
                category=str(data.get("category", "uncategorised")),
                description=str(data.get("description", "")),
                source=str(data.get("source", "internal")),
                expect_rules=tuple(data.get("expect_rules", [])),
                forbid_rules=tuple(data.get("forbid_rules", [])),
                forbid_rules_entirely=tuple(data.get("forbid_rules_entirely", [])),
                expect_verdict=str(data.get("expect_verdict", "")),
            )
        )
    return cases


def run_case(case: Case, config: Config | None = None) -> CaseResult:
    from skillsniff.engine import scan

    config = config or Config()
    started = time.perf_counter()
    try:
        result = scan(case.path, config)
    except Exception as exc:
        return CaseResult(
            case=case,
            verdict=Verdict.INCONCLUSIVE,
            flagged=False,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            error=f"{type(exc).__name__}: {exc}",
        )
    elapsed = (time.perf_counter() - started) * 1000

    if not result.skills:
        return CaseResult(
            case=case, verdict=Verdict.INCONCLUSIVE, flagged=False,
            elapsed_ms=elapsed, error="no skill found in case directory",
        )

    fired = {f.rule_id for f in result.all_findings}
    actionable = {
        f.rule_id for f in result.all_findings if f.severity.rank <= Severity.MEDIUM.rank
    }
    verdict = result.verdict

    forbidden = [r for r in case.forbid_rules if r in actionable]
    forbidden += [
        r for r in case.forbid_rules_entirely if r in fired and r not in forbidden
    ]

    return CaseResult(
        case=case,
        verdict=verdict,
        flagged=verdict in FLAGGED,
        rules_fired=fired,
        rules_actionable=actionable,
        # A malicious case must trip its expected rule as an *actionable*
        # finding: a downgraded note would mean the rule fired but would not
        # stop anyone, which is not detection.
        missing_expected=[
            r
            for r in case.expect_rules
            if r not in (actionable if case.is_malicious else fired)
        ],
        forbidden_fired=forbidden,
        verdict_mismatch=bool(case.expect_verdict) and verdict.value != case.expect_verdict.upper(),
        elapsed_ms=elapsed,
    )


def run_benchmark(corpus: Path, config: Config | None = None) -> BenchmarkReport:
    from skillsniff import __version__

    cases = load_cases(corpus)
    if not cases:
        raise UsageError(f"no benchmark cases found under {corpus}")

    report = BenchmarkReport(corpus=str(corpus), tool_version=__version__)
    for case in cases:
        result = run_case(case, config)
        report.results.append(result)
        report.total_elapsed_ms += result.elapsed_ms

        report.overall.add(result.outcome)
        report.by_source.setdefault(case.source, Metrics()).add(result.outcome)
        report.by_category.setdefault(case.category, Metrics()).add(result.outcome)

    return report
