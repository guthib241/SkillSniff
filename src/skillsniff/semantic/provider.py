"""The semantic provider contract.

An implementation of :class:`SemanticProvider` may use a language model to
answer questions static analysis cannot: does this skill's described purpose
match what its code does, is this ambiguous instruction an injection, does this
workflow make sense. Those are judgments, and this module's job is to make sure
they are never mistaken for measurements.

No provider ships. :class:`NullProvider` is the default and does nothing, so
``enable_semantic = true`` with no provider configured is a no-op rather than a
silent behaviour change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from skillsniff.model.finding import Confidence, Evidence, Finding, Severity

#: Delimiters for untrusted content. Chosen to be long and unlikely to occur in
#: skill text; a provider MUST reject a request whose content contains them
#: rather than escaping, because escaping is where this kind of boundary fails.
UNTRUSTED_OPEN = "<<<SKILLSNIFF_UNTRUSTED_ARTIFACT_CONTENT>>>"
UNTRUSTED_CLOSE = "<<<END_SKILLSNIFF_UNTRUSTED_ARTIFACT_CONTENT>>>"

#: Semantic findings are advisory. Capping confidence here, rather than trusting
#: providers to behave, is what keeps a model's opinion from reaching the
#: critical-finding gate in the risk model.
MAX_SEMANTIC_CONFIDENCE = Confidence.MEDIUM
MAX_SEMANTIC_SEVERITY = Severity.HIGH


class SemanticTask(str, Enum):
    """What a provider is being asked to judge."""

    INTENT_MISMATCH = "intent-mismatch"
    INJECTION_CLASSIFICATION = "injection-classification"
    CAPABILITY_INTERPRETATION = "capability-interpretation"
    WORKFLOW_PLAUSIBILITY = "workflow-plausibility"
    AMBIGUOUS_FINDING_REVIEW = "ambiguous-finding-review"

    @property
    def question(self) -> str:
        """The analyst-side question. Never mixed with artifact content."""
        return {
            SemanticTask.INTENT_MISMATCH: (
                "Does the skill's stated purpose account for the capabilities observed "
                "in its code and instructions?"
            ),
            SemanticTask.INJECTION_CLASSIFICATION: (
                "Is the quoted span an instruction directed at the agent, or is it "
                "documentation describing such an instruction?"
            ),
            SemanticTask.CAPABILITY_INTERPRETATION: (
                "Which of the listed capabilities does the quoted content actually exercise?"
            ),
            SemanticTask.WORKFLOW_PLAUSIBILITY: (
                "Is the described workflow a plausible way to accomplish the stated purpose?"
            ),
            SemanticTask.AMBIGUOUS_FINDING_REVIEW: (
                "Given the evidence, is this static finding likely to be a true positive?"
            ),
        }[self]


class UntrustedContentError(ValueError):
    """Raised when artifact content would break the untrusted envelope."""


def wrap_untrusted(content: str) -> str:
    """Wrap artifact content in its untrusted envelope.

    Refuses rather than escapes if the content already contains a delimiter. A
    skill that includes the delimiter is trying to break out of the envelope,
    and escaping would be an arms race against an attacker who controls the
    entire input.
    """
    if UNTRUSTED_OPEN in content or UNTRUSTED_CLOSE in content:
        raise UntrustedContentError(
            "artifact content contains the untrusted-content delimiter; refusing to "
            "construct a semantic request for it"
        )
    return f"{UNTRUSTED_OPEN}\n{content}\n{UNTRUSTED_CLOSE}"


@dataclass(frozen=True)
class SemanticRequest:
    """One question, with the artifact content it is about.

    ``question`` and ``context`` are analyst-authored. ``untrusted_content`` is
    attacker-controlled and is the only field a provider may not treat as
    instruction.
    """

    task: SemanticTask
    question: str
    untrusted_content: str
    skill: str
    path: str
    line: int | None = None
    #: Analyst-authored facts the provider may rely on (capability names,
    #: rule ids). Never artifact text.
    context: dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        task: SemanticTask,
        content: str,
        *,
        skill: str,
        path: str,
        line: int | None = None,
        context: dict[str, str] | None = None,
    ) -> SemanticRequest:
        return cls(
            task=task,
            question=task.question,
            untrusted_content=wrap_untrusted(content),
            skill=skill,
            path=path,
            line=line,
            context=dict(context or {}),
        )

    @property
    def content_is_enveloped(self) -> bool:
        return self.untrusted_content.startswith(UNTRUSTED_OPEN) and self.untrusted_content.endswith(
            UNTRUSTED_CLOSE
        )


@dataclass(frozen=True)
class SemanticFinding:
    """A provider's judgment. Deliberately not a :class:`Finding`.

    Converting to a Finding goes through :meth:`to_finding`, which is where the
    advisory flag and the confidence cap are applied. A provider cannot emit a
    Finding directly, so it cannot emit one that looks deterministic.
    """

    task: SemanticTask
    verdict: str
    rationale: str
    confidence: Confidence
    severity: Severity = Severity.MEDIUM
    quoted_evidence: str = ""

    def to_finding(self, request: SemanticRequest, rule_id: str = "SEM001") -> Finding:
        confidence = (
            self.confidence
            if self.confidence.rank >= MAX_SEMANTIC_CONFIDENCE.rank
            else MAX_SEMANTIC_CONFIDENCE
        )
        severity = (
            self.severity
            if self.severity.rank >= MAX_SEMANTIC_SEVERITY.rank
            else MAX_SEMANTIC_SEVERITY
        )
        return Finding(
            rule_id=rule_id,
            title=f"Semantic judgment: {self.verdict}",
            severity=severity,
            confidence=confidence,
            skill=request.skill,
            family="CON",
            message=self.rationale,
            evidence=[
                Evidence(
                    path=request.path,
                    line=request.line,
                    excerpt=self.quoted_evidence[:200],
                    note="semantic judgment from an optional model-based analyser, not a "
                    "deterministic detection",
                )
            ],
            explanation=(
                "This finding comes from the optional semantic layer. It is a model's "
                "interpretation of the content, not a measurement of it."
            ),
            impact="Treat as a prompt to look, not as evidence of a defect.",
            remediation="Review the cited content and decide for yourself.",
            advisory=True,
        )


@runtime_checkable
class SemanticProvider(Protocol):
    """What an implementation must provide.

    Implementations MUST:

    * treat ``request.untrusted_content`` strictly as data — never place it in a
      system or developer position, and never concatenate it with instructions;
    * return ``None`` rather than guessing when the answer is unclear;
    * never make a network call unless the caller has opted in explicitly;
    * be side-effect free with respect to the scanned artifact.
    """

    name: str

    def analyze(self, request: SemanticRequest) -> SemanticFinding | None: ...


class NullProvider:
    """The default. Makes no call, returns nothing, changes nothing.

    Its existence means enabling the semantic layer without configuring a
    provider is a visible no-op rather than an error or a silent change.
    """

    name = "null"

    def analyze(self, request: SemanticRequest) -> SemanticFinding | None:
        del request
        return None


def run_semantic_analysis(
    provider: SemanticProvider,
    requests: list[SemanticRequest],
) -> list[Finding]:
    """Run a provider over requests, enforcing the boundary on the way out.

    A provider that returns something malformed is dropped rather than trusted:
    this layer is optional, so failing closed costs nothing.
    """
    findings: list[Finding] = []
    for request in requests:
        if not request.content_is_enveloped:
            # Never send content that is not properly enveloped.
            continue
        try:
            result = provider.analyze(request)
        except Exception:  # noqa: S112 - see below
            # An optional layer must never break a scan. There is deliberately no
            # logging here: the exception may carry provider-side detail derived
            # from artifact content, and this layer's whole purpose is to keep
            # that content from leaking into places it was not meant to reach.
            continue
        if result is None or not isinstance(result, SemanticFinding):
            continue
        if not result.verdict or not result.rationale:
            continue
        findings.append(result.to_finding(request))
    return findings
