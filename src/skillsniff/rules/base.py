"""Rule taxonomy, metadata, and registry.

Every rule is registered with a :class:`RuleMeta` that carries not just what the
rule detects but *why it matters*, *what it cannot see*, and *what to do about
it*. That metadata is the single source of truth behind ``skillsniff rules``,
``skillsniff explain``, the SARIF rule descriptors, and the enrichment attached
to each emitted finding.

The previous generation of this tool kept explanations in a hand-maintained
dictionary in the CLI, which silently covered only one of the three rule packs,
so ``explain SPEC005`` failed. Deriving everything from the registry makes that
class of drift impossible.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from skillsniff.model.finding import Confidence, Evidence, Finding, Severity

if TYPE_CHECKING:
    from skillsniff.analysis.context import AnalysisContext


class Family(str, Enum):
    """Rule families.

    The security families follow the taxonomy the project standardised on; SPEC
    and QUA are deliberately *outside* it, because specification compliance and
    documentation quality are not security risk and must never be traded against
    it.
    """

    INJ = "INJ"  # prompt / instruction injection
    EXF = "EXF"  # exfiltration
    CRE = "CRE"  # credential and secret access
    EXE = "EXE"  # execution
    PRV = "PRV"  # privilege and safety bypass
    SUP = "SUP"  # supply chain
    MEM = "MEM"  # memory and state
    MCP = "MCP"  # tool and MCP abuse
    EVA = "EVA"  # scanner evasion
    OBS = "OBS"  # obfuscation
    PER = "PER"  # persistence
    NET = "NET"  # network behaviour
    CON = "CON"  # capability / contract mismatch
    ARC = "ARC"  # archive and nested artifact risk
    SPEC = "SPEC"  # specification compliance
    QUA = "QUA"  # authoring quality

    @property
    def label(self) -> str:
        return _FAMILY_LABELS[self]

    @property
    def is_security(self) -> bool:
        return self not in (Family.SPEC, Family.QUA)


_FAMILY_LABELS: dict[Family, str] = {
    Family.INJ: "Prompt / instruction injection",
    Family.EXF: "Exfiltration",
    Family.CRE: "Credential and secret access",
    Family.EXE: "Execution",
    Family.PRV: "Privilege and safety bypass",
    Family.SUP: "Supply chain",
    Family.MEM: "Memory and state",
    Family.MCP: "Tool and MCP abuse",
    Family.EVA: "Scanner evasion",
    Family.OBS: "Obfuscation",
    Family.PER: "Persistence",
    Family.NET: "Network behaviour",
    Family.CON: "Capability / contract mismatch",
    Family.ARC: "Archive and nested artifact risk",
    Family.SPEC: "Specification compliance",
    Family.QUA: "Authoring quality",
}


@dataclass(frozen=True)
class RuleMeta:
    """Everything that is true about a rule regardless of what it scanned."""

    id: str
    title: str
    family: Family
    severity: Severity
    confidence: Confidence
    #: One paragraph: what the rule looks for and how.
    explanation: str
    #: What an attacker gains if this finding is real.
    impact: str
    #: What the author should actually do.
    remediation: str
    #: Honest statement of the rule's blind spots. Required, because a security
    #: tool that documents only its strengths teaches false confidence.
    limitations: str = ""
    references: tuple[str, ...] = ()
    taxonomy: tuple[str, ...] = ()
    #: Rules off by default are experimental or noisy in general corpora.
    default_enabled: bool = True
    experimental: bool = False

    def __post_init__(self) -> None:
        if not self.id.startswith(self.family.value):
            raise ValueError(f"rule id {self.id!r} must start with family {self.family.value!r}")


#: A rule is any callable taking the analysis context and yielding findings.
Rule = Callable[["AnalysisContext"], Iterable[Finding]]


class Registry:
    """Holds rule metadata and the callables that implement them."""

    def __init__(self) -> None:
        self._meta: dict[str, RuleMeta] = {}
        self._rules: dict[str, Rule] = {}

    # -- registration -------------------------------------------------------

    def define(self, meta: RuleMeta) -> RuleMeta:
        if meta.id in self._meta:
            raise ValueError(f"duplicate rule id: {meta.id}")
        self._meta[meta.id] = meta
        return meta

    def define_all(self, metas: Iterable[RuleMeta]) -> None:
        for meta in metas:
            self.define(meta)

    def implement(self, *rule_ids: str) -> Callable[[Rule], Rule]:
        """Attach a callable to one or more previously-defined rule ids."""

        def decorator(func: Rule) -> Rule:
            for rule_id in rule_ids:
                if rule_id not in self._meta:
                    raise ValueError(f"rule {rule_id!r} implemented before it was defined")
                self._rules[rule_id] = func
            return func

        return decorator

    # -- lookup -------------------------------------------------------------

    def meta(self, rule_id: str) -> RuleMeta | None:
        return self._meta.get(rule_id.upper())

    def all_meta(self) -> list[RuleMeta]:
        return sorted(self._meta.values(), key=lambda m: (m.family.value, m.id))

    def by_family(self, family: Family) -> list[RuleMeta]:
        return [m for m in self.all_meta() if m.family is family]

    def families(self) -> list[Family]:
        return sorted({m.family for m in self._meta.values()}, key=lambda f: f.value)

    def callables(self) -> dict[str, Rule]:
        """Unique rule callables, keyed by the first id that registered them."""
        seen: dict[int, str] = {}
        out: dict[str, Rule] = {}
        for rule_id, func in self._rules.items():
            marker = id(func)
            if marker in seen:
                continue
            seen[marker] = rule_id
            out[rule_id] = func
        return out

    def implemented_ids(self) -> set[str]:
        return set(self._rules)

    def unimplemented(self) -> list[str]:
        """Defined but not implemented — a bug, and the self-test asserts it is empty."""
        return sorted(set(self._meta) - set(self._rules))

    def __contains__(self, rule_id: object) -> bool:
        return isinstance(rule_id, str) and rule_id.upper() in self._meta

    def __len__(self) -> int:
        return len(self._meta)


registry = Registry()


def emit(
    rule_id: str,
    skill: str,
    *,
    message: str = "",
    evidence: Iterable[Evidence] = (),
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    related: Iterable[str] = (),
    advisory: bool = False,
) -> Finding:
    """Build a fully-enriched finding from the registry entry for ``rule_id``.

    Rules call this rather than constructing :class:`Finding` directly, so every
    finding automatically carries its explanation, impact, remediation, and
    references. ``severity``/``confidence`` override the registry default for the
    cases where a rule can tell that a particular sighting is stronger or weaker
    than the general case.
    """
    meta = registry.meta(rule_id)
    if meta is None:
        raise KeyError(f"unknown rule id: {rule_id}")
    return Finding(
        rule_id=meta.id,
        title=meta.title,
        severity=severity or meta.severity,
        confidence=confidence or meta.confidence,
        skill=skill,
        evidence=list(evidence),
        message=message,
        family=meta.family.value,
        explanation=meta.explanation,
        impact=meta.impact,
        remediation=meta.remediation,
        references=list(meta.references),
        taxonomy=list(meta.taxonomy),
        related=list(related),
        advisory=advisory or meta.experimental,
    )
