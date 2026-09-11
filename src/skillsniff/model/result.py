"""Scan results and the risk model.

The single most important design decision in this file is that there is no
single score. The previous generation of this tool computed one 0–100 number
across specification, quality, and security findings, which meant excellent
documentation could numerically offset a credential exfiltration path. That is
precisely backwards.

Instead risk is reported along independent dimensions, and the overall verdict
is produced by *gating rules* rather than arithmetic. A critical security finding
sets the verdict regardless of how good everything else is, and no amount of
quality can move it. Coverage is a dimension too: a scan that could not read
half the artifact cannot return a clean verdict, only an inconclusive one.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from skillsniff.core.limits import Budget
from skillsniff.model.capability import CapabilitySurface
from skillsniff.model.finding import Confidence, Finding, Severity


class Verdict(str, Enum):
    """The overall judgement for one skill.

    Deliberately not "safe"/"unsafe". A static scan cannot establish safety, and
    wording that implies it would be the most harmful thing this tool could do.
    """

    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    CAUTION = "CAUTION"
    CLEAR = "CLEAR"
    INCONCLUSIVE = "INCONCLUSIVE"

    @property
    def summary(self) -> str:
        return {
            Verdict.BLOCK: "Critical security findings; do not install without remediation",
            Verdict.REVIEW: "Security findings that need a human decision before use",
            Verdict.CAUTION: "Lower-severity findings worth reading before use",
            Verdict.CLEAR: "No issues detected by the enabled checks",
            Verdict.INCONCLUSIVE: "Too much of the artifact could not be analysed to judge",
        }[self]

    @property
    def rank(self) -> int:
        return {
            Verdict.BLOCK: 0,
            Verdict.INCONCLUSIVE: 1,
            Verdict.REVIEW: 2,
            Verdict.CAUTION: 3,
            Verdict.CLEAR: 4,
        }[self]


class RiskBand(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


def _band_from(findings: Iterable[Finding]) -> RiskBand:
    """Worst severity present, ignoring low-confidence advisory findings."""
    band = RiskBand.NONE
    for finding in findings:
        if finding.advisory and finding.confidence is Confidence.LOW:
            continue
        candidate = {
            Severity.CRITICAL: RiskBand.CRITICAL,
            Severity.HIGH: RiskBand.HIGH,
            Severity.MEDIUM: RiskBand.MEDIUM,
            Severity.LOW: RiskBand.LOW,
            Severity.INFO: RiskBand.NONE,
        }[finding.severity]
        if candidate.rank > band.rank:
            band = candidate
    return band


@dataclass
class Dimension:
    """One axis of risk, reported independently of the others."""

    key: str
    label: str
    band: RiskBand
    findings: list[Finding] = field(default_factory=list)
    note: str = ""

    @property
    def count(self) -> int:
        return len(self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "band": self.band.value,
            "findings": self.count,
            "note": self.note,
        }


#: Which rule families feed which dimension. SPEC and QUA are deliberately
#: isolated so they cannot influence the security verdict in either direction.
DIMENSION_FAMILIES: dict[str, tuple[str, ...]] = {
    "security": ("INJ", "EXF", "CRE", "EXE", "PRV", "OBS", "EVA", "PER", "MEM", "MCP"),
    "capability": ("CON",),
    "supply_chain": ("SUP", "NET", "ARC"),
    "specification": ("SPEC",),
    "quality": ("QUA",),
}

#: The dimensions excluded from the verdict gates, per the note above. Keeping
#: them out of the gates is right: how a skill is *written* must not read as a
#: security judgement. But it makes the bare ``CLEAR`` sentence ("no issues
#: detected") false whenever one of these families fired, and that is the one
#: place this tool could talk a reader out of looking at a real finding. The
#: verdict stays CLEAR; the sentence has to say what was found anyway.
ISOLATED_DIMENSIONS: tuple[str, ...] = ("specification", "quality")


def _clear_summary(isolated: int) -> str:
    """The ``CLEAR`` sentence, refined by findings the gates cannot see."""
    if not isolated:
        return Verdict.CLEAR.summary
    noun = "finding" if isolated == 1 else "findings"
    return f"No security findings; {isolated} specification/quality {noun} to review"


DIMENSION_LABELS = {
    "security": "Security risk",
    "capability": "Capability exposure",
    "supply_chain": "Supply-chain risk",
    "specification": "Specification compliance",
    "quality": "Authoring quality",
}


@dataclass
class Coverage:
    """What the scan actually managed to inspect."""

    files_analyzed: int = 0
    files_discovered: int = 0
    archives_expanded: int = 0
    encoded_regions: int = 0
    unicode_checked: bool = True
    confidence: str = "HIGH"
    gaps: list[dict[str, str]] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    @property
    def complete(self) -> bool:
        return not self.gaps and self.files_analyzed >= self.files_discovered

    @classmethod
    def from_budget(cls, budget: Budget) -> Coverage:
        return cls(
            files_analyzed=budget.files_analyzed,
            files_discovered=budget.files_discovered,
            archives_expanded=budget.archives_expanded,
            encoded_regions=budget.encoded_regions_inspected,
            confidence=budget.confidence(),
            gaps=[g.as_dict() for g in budget.gaps],
            elapsed_seconds=round(budget.elapsed, 4),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "files_analyzed": self.files_analyzed,
            "files_discovered": self.files_discovered,
            "archives_expanded": self.archives_expanded,
            "encoded_regions_inspected": self.encoded_regions,
            "unicode_checked": self.unicode_checked,
            "confidence": self.confidence,
            "complete": self.complete,
            "elapsed_seconds": self.elapsed_seconds,
            "gaps": self.gaps,
        }


@dataclass
class RiskAssessment:
    """The full, multi-dimensional risk picture for one skill."""

    dimensions: dict[str, Dimension] = field(default_factory=dict)
    verdict: Verdict = Verdict.CLEAR
    rationale: list[str] = field(default_factory=list)

    def band(self, key: str) -> RiskBand:
        dimension = self.dimensions.get(key)
        return dimension.band if dimension else RiskBand.NONE

    @property
    def isolated_findings(self) -> list[Finding]:
        """Findings in dimensions the verdict gates deliberately ignore."""
        out: list[Finding] = []
        for key in ISOLATED_DIMENSIONS:
            dimension = self.dimensions.get(key)
            if dimension:
                out.extend(dimension.findings)
        return out

    @property
    def summary(self) -> str:
        """The verdict sentence, truthful about findings the gates ignore."""
        if self.verdict is not Verdict.CLEAR:
            return self.verdict.summary
        return _clear_summary(len(self.isolated_findings))

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "summary": self.summary,
            "rationale": list(self.rationale),
            "dimensions": {k: v.as_dict() for k, v in self.dimensions.items()},
        }


def assess(findings: list[Finding], coverage: Coverage) -> RiskAssessment:
    """Compute dimensions and derive a verdict by gating, not by arithmetic."""
    assessment = RiskAssessment()

    for key, families in DIMENSION_FAMILIES.items():
        subset = [f for f in findings if f.family in families]
        assessment.dimensions[key] = Dimension(
            key=key,
            label=DIMENSION_LABELS[key],
            band=_band_from(subset),
            findings=subset,
        )

    security = assessment.dimensions["security"]
    capability = assessment.dimensions["capability"]
    supply = assessment.dimensions["supply_chain"]
    rationale: list[str] = []

    # Gate 1 — a critical finding in any security-bearing dimension is decisive.
    # Deliberately spans capability and supply-chain as well as security: an
    # archive path traversal (ARC) or a skill that fetches its instructions from
    # a mutable URL (SUP) is critical regardless of which family it lives in,
    # and scoping this gate to one dimension quietly downgraded both.
    critical = [
        f
        for f in (*security.findings, *capability.findings, *supply.findings)
        if f.severity is Severity.CRITICAL and f.confidence is not Confidence.LOW
    ]
    if critical:
        assessment.verdict = Verdict.BLOCK
        rationale.append(
            f"{len(critical)} critical security finding(s): "
            + ", ".join(sorted({f.rule_id for f in critical}))
        )
        assessment.rationale = rationale
        return assessment

    # Gate 2 — coverage. A scan that could not read the artifact cannot clear it.
    if coverage.confidence == "LOW":
        assessment.verdict = Verdict.INCONCLUSIVE
        rationale.append(
            f"analysis coverage is LOW ({coverage.files_analyzed}/{coverage.files_discovered} "
            f"files analysed, {len(coverage.gaps)} gap(s)); a clean result cannot be asserted"
        )
        assessment.rationale = rationale
        return assessment

    # Gate 3 — high-severity security, capability, or supply-chain risk.
    high_bands = [
        d for d in (security, capability, supply) if d.band.rank >= RiskBand.HIGH.rank
    ]
    if high_bands:
        assessment.verdict = Verdict.REVIEW
        for dimension in high_bands:
            rules = sorted({f.rule_id for f in dimension.findings if f.severity.rank <= Severity.HIGH.rank})
            rationale.append(f"{dimension.label.lower()} is {dimension.band.value}: {', '.join(rules)}")
        assessment.rationale = rationale
        return assessment

    # Gate 4 — medium risk in a security-bearing dimension.
    medium_bands = [
        d for d in (security, capability, supply) if d.band.rank >= RiskBand.MEDIUM.rank
    ]
    if medium_bands:
        assessment.verdict = Verdict.CAUTION
        for dimension in medium_bands:
            rationale.append(f"{dimension.label.lower()} is {dimension.band.value}")
        assessment.rationale = rationale
        return assessment

    if coverage.confidence == "MEDIUM":
        rationale.append(
            f"coverage is MEDIUM: {len(coverage.gaps)} part(s) of the artifact were not fully inspected"
        )
    if any(d.band is not RiskBand.NONE for d in (security, capability, supply)):
        assessment.verdict = Verdict.CAUTION
        rationale.append("low-severity findings present")
    else:
        assessment.verdict = Verdict.CLEAR
        rationale.append("no security, capability, or supply-chain findings from the enabled checks")

    assessment.rationale = rationale
    return assessment


@dataclass
class SkillResult:
    """The complete result for one skill."""

    name: str
    path: str
    findings: list[Finding] = field(default_factory=list)
    capabilities: CapabilitySurface = field(default_factory=CapabilitySurface)
    coverage: Coverage = field(default_factory=Coverage)
    risk: RiskAssessment = field(default_factory=RiskAssessment)
    externals: list[dict[str, Any]] = field(default_factory=list)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    description: str = ""
    version: str = ""
    declared_tools: list[str] = field(default_factory=list)
    file_count: int = 0
    total_bytes: int = 0

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for finding in self.findings:
            out[finding.severity.value] += 1
        return out

    def worst(self) -> Severity | None:
        return min((f.severity for f in self.findings), key=lambda s: s.rank, default=None)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "description": self.description,
            "version": self.version,
            "declared_tools": list(self.declared_tools),
            "verdict": self.risk.verdict.value,
            "risk": self.risk.as_dict(),
            "coverage": self.coverage.as_dict(),
            "counts": self.counts(),
            "capabilities": self.capabilities.as_dict(),
            "external_resources": self.externals,
            "dependencies": self.dependencies,
            "findings": [f.as_dict() for f in self.findings],
            "files": self.file_count,
            "bytes": self.total_bytes,
        }


@dataclass
class ScanResult:
    """The result of one invocation, across every skill scanned."""

    skills: list[SkillResult] = field(default_factory=list)
    tool_version: str = ""
    scanned_path: str = ""
    rules_run: int = 0
    errors: list[str] = field(default_factory=list)
    #: Findings hidden by a baseline. Always reported: a baseline whose effect is
    #: invisible is indistinguishable from a scanner that found nothing.
    baseline_suppressed: int = 0
    baseline_path: str = ""
    #: Baseline entries that matched nothing — findings since fixed.
    baseline_stale: int = 0

    @property
    def all_findings(self) -> list[Finding]:
        return [f for s in self.skills for f in s.findings]

    @property
    def verdict(self) -> Verdict:
        """The worst verdict across all skills.

        Deliberately worst-of, never an average. Averaging is how one dangerous
        skill disappears behind nine clean ones.
        """
        if not self.skills:
            return Verdict.CLEAR
        return min((s.risk.verdict for s in self.skills), key=lambda v: v.rank)

    @property
    def summary(self) -> str:
        """The overall sentence, truthful about findings the gates ignore."""
        if self.verdict is not Verdict.CLEAR:
            return self.verdict.summary
        return _clear_summary(sum(len(s.risk.isolated_findings) for s in self.skills))

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for finding in self.all_findings:
            out[finding.severity.value] += 1
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": "skillsniff",
            "version": self.tool_version,
            "scanned_path": self.scanned_path,
            "verdict": self.verdict.value,
            "summary": self.summary,
            "skills_scanned": len(self.skills),
            "rules_run": self.rules_run,
            "counts": self.counts(),
            "skills": [s.as_dict() for s in self.skills],
            "errors": list(self.errors),
            **(
                {
                    "baseline": {
                        "path": self.baseline_path,
                        "suppressed": self.baseline_suppressed,
                        "stale_entries": self.baseline_stale,
                    }
                }
                if self.baseline_path
                else {}
            ),
        }
