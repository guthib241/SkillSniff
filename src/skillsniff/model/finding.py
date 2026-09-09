"""The finding model.

A finding is a claim about an artifact. The project's second principle is
"evidence over assertions", so the type makes evidence structurally mandatory:
you cannot construct a :class:`Finding` without saying where you saw the thing
you are reporting.

Severity answers "how bad if true". Confidence answers "how sure are we".
Keeping them separate is what lets the risk model surface a high-severity,
low-confidence finding for review without failing a build on a guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """How much damage the finding implies if it is real."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank  # lower rank == more severe

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from exc

    @classmethod
    def at_or_above(cls, threshold: Severity) -> set[Severity]:
        return {s for s in cls if s.rank <= threshold.rank}


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Confidence(str, Enum):
    """How certain the detection is, independent of how bad it would be.

    HIGH
        The evidence is essentially unambiguous — a decoded payload that pipes
        to a shell, a committed private key.
    MEDIUM
        A strong pattern that has plausible benign explanations in some contexts.
    LOW
        A heuristic or correlation worth a human's attention, not a build failure.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"high": 0, "medium": 1, "low": 2}[self.value]


@dataclass(frozen=True)
class Evidence:
    """Where a finding was observed, and what was observed there.

    ``decode_chain`` is set when the evidence was only visible after decoding,
    e.g. ``base64 -> hex``. Reporting it is the difference between "we found a
    payload" and "we found a payload you could not have seen by reading the file".
    """

    path: str
    line: int | None = None
    end_line: int | None = None
    column: int | None = None
    excerpt: str = ""
    decode_chain: str = ""
    note: str = ""

    @property
    def location(self) -> str:
        if self.line is None:
            return self.path
        return f"{self.path}:{self.line}"

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"path": self.path}
        if self.line is not None:
            payload["line"] = self.line
        if self.end_line is not None:
            payload["end_line"] = self.end_line
        if self.column is not None:
            payload["column"] = self.column
        if self.excerpt:
            payload["excerpt"] = self.excerpt
        if self.decode_chain:
            payload["decode_chain"] = self.decode_chain
        if self.note:
            payload["note"] = self.note
        return payload


@dataclass
class Finding:
    """A single evidence-backed claim about a skill."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    skill: str
    evidence: list[Evidence] = field(default_factory=list)
    #: Free-form, rule-specific detail. The rule's static explanation lives in
    #: the registry; this is what was true *of this artifact*.
    message: str = ""
    #: Populated from the rule registry at emit time so a serialised finding is
    #: self-contained and a consumer never has to look the rule up.
    family: str = ""
    explanation: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    taxonomy: list[str] = field(default_factory=list)
    #: Rule IDs whose findings combined to produce this one (compound risks).
    related: list[str] = field(default_factory=list)
    #: True when the finding came from an optional/experimental analyser (for
    #: example the semantic layer), so reports never present a model's judgment
    #: as a deterministic fact.
    advisory: bool = False

    @property
    def primary(self) -> Evidence | None:
        return self.evidence[0] if self.evidence else None

    @property
    def location(self) -> str:
        return self.primary.location if self.primary else self.skill

    def sort_key(self) -> tuple[int, int, str, str, int]:
        primary = self.primary
        return (
            self.severity.rank,
            self.confidence.rank,
            self.skill,
            self.rule_id,
            primary.line or 0 if primary else 0,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "family": self.family,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "skill": self.skill,
            "message": self.message,
            "evidence": [e.as_dict() for e in self.evidence],
            "explanation": self.explanation,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": list(self.references),
            "taxonomy": list(self.taxonomy),
            "related": list(self.related),
            "advisory": self.advisory,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.sort_key())


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that are the same rule at the same location.

    Rules that scan both the raw and the normalised projection of a file will
    legitimately fire twice on the same span; reporting that twice is noise.
    Distinct locations are preserved — that is signal, not duplication.
    """
    seen: dict[tuple[str, str, str, int | None], Finding] = {}
    for finding in findings:
        primary = finding.primary
        key = (
            finding.rule_id,
            finding.skill,
            primary.path if primary else "",
            primary.line if primary else None,
        )
        existing = seen.get(key)
        if existing is None:
            seen[key] = finding
            continue
        # Keep the one with more evidence, preferring a decoded sighting since
        # it carries strictly more information about how the content was hidden.
        if len(finding.evidence) > len(existing.evidence) or (
            primary and primary.decode_chain and not (existing.primary and existing.primary.decode_chain)
        ):
            seen[key] = finding
    return sort_findings(list(seen.values()))
