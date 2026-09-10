"""Compound-risk rules (CON family, compound subset).

Some capabilities are unremarkable alone and dangerous together. The canonical
case is the "lethal trifecta": access to private data, exposure to untrusted
content, and the ability to communicate externally. Any two are usually fine.
All three means a prompt injection delivered through the untrusted channel can
read the private data and send it out, with no further vulnerability required.

These rules deliberately do *not* treat every combination as malicious. Each one
requires evidence for each leg, and confidence reflects how directly that
evidence was obtained: an AST-observed capability contributes more than a
capability inferred from prose.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from skillsniff.analysis.context import AnalysisContext
from skillsniff.model.capability import Capability, Source
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity
from skillsniff.rules.base import Family, RuleMeta, emit, registry

TRIFECTA_REF = "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/"

#: Each leg of the trifecta, expressed as the capabilities that satisfy it.
PRIVATE_DATA = frozenset(
    {
        Capability.SECRET_ACCESS,
        Capability.CREDENTIAL_HANDLING,
        Capability.ENV_READ,
        Capability.FS_READ,
    }
)
#: Untrusted input is content the skill *pulls in* — remote instructions,
#: fetched documents, tool output. Note that this overlaps with EXTERNAL_COMMS
#: at the capability level (both are "the network"), so the trifecta check below
#: additionally requires the two legs to be satisfied by *distinct sightings*.
#: Without that, a single `requests.post` would satisfy two legs on its own and
#: manufacture a trifecta out of one call.
UNTRUSTED_INPUT = frozenset(
    {
        Capability.REMOTE_INSTRUCTIONS,
        Capability.NET_FETCH,
    }
)
EXTERNAL_COMMS = frozenset(
    {
        Capability.NET_OUTBOUND,
    }
)

registry.define_all(
    [
        RuleMeta(
            id="CON010",
            title="Lethal trifecta: private data, untrusted input, and external communication",
            family=Family.CON,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill combines access to private data (credentials, environment, or the "
                "filesystem), exposure to untrusted external content, and the ability to send "
                "data outward. Each leg is reported with its own evidence."
            ),
            impact=(
                "An injection delivered through the untrusted content can instruct the agent to "
                "read the private data and transmit it. No software vulnerability is required: "
                "the combination is the vulnerability."
            ),
            remediation=(
                "Break one leg. Most often the cheapest is to remove the outbound channel, or "
                "to restrict it to a fixed allowlisted destination that cannot receive "
                "arbitrary data."
            ),
            limitations=(
                "Presence of all three legs is not proof of a vulnerability; a skill can hold "
                "all three and handle them safely. This is a prompt to review the data path, "
                "not a defect on its own."
            ),
            references=(TRIFECTA_REF,),
            taxonomy=("LLM01:PromptInjection", "LLM06:ExcessiveAgency"),
        ),
        RuleMeta(
            id="CON011",
            title="Credential access combined with network egress",
            family=Family.CON,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill both reads credentials and makes outbound network requests. This is "
                "the two-step shape of exfiltration, reported even when no direct dataflow "
                "between them was observed."
            ),
            impact="Every precondition for credential exfiltration is present in one artifact.",
            remediation=(
                "Separate the concerns, or state plainly which credential is sent to which "
                "service and why."
            ),
            limitations=(
                "Legitimate for any skill that authenticates to an API, which is most of them. "
                "This rule reports co-occurrence, not a data path; EXF001 is the higher-"
                "confidence version, based on dataflow actually observed in the AST."
            ),
            references=(TRIFECTA_REF,),
        ),
        RuleMeta(
            id="CON012",
            title="Untrusted content combined with shell execution",
            family=Family.CON,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill retrieves remote content and also executes shell commands, so "
                "attacker-influenced text and a command interpreter are present together."
            ),
            limitations=(
                "Presence of both capabilities is not proof they are connected. No dataflow "
                "between the fetched content and the command is established; this is a prompt "
                "to check the path."
            ),
            impact=(
                "Content fetched from a remote source can steer command construction, turning "
                "a content compromise into command execution."
            ),
            remediation=(
                "Never interpolate fetched content into a command. Use argument lists and "
                "validate against an allowlist."
            ),
            references=(TRIFECTA_REF,),
        ),
        RuleMeta(
            id="CON013",
            title="Mutable dependency combined with privileged execution",
            family=Family.CON,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill depends on something that can change after review and also executes "
                "code with privilege."
            ),
            impact=(
                "A future version of the dependency inherits the skill's execution privilege "
                "without any review step."
            ),
            remediation="Pin the dependency, or drop the privileged execution.",
            references=(TRIFECTA_REF,),
        ),
        RuleMeta(
            id="CON014",
            title="Persistence combined with privileged capability",
            family=Family.CON,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill writes persistent state or configuration and also holds a privileged "
                "capability such as execution, network access, or credential access."
            ),
            limitations=(
                "Legitimate for a skill that caches results and also makes network calls. "
                "Judge by what is persisted and where."
            ),
            impact=(
                "A one-time execution becomes a standing one: the persisted state re-establishes "
                "the privileged behaviour in future sessions."
            ),
            remediation="Remove the persistence, or narrow what is persisted to inert data.",
            references=(TRIFECTA_REF,),
        ),
    ]
)


@dataclass
class _Leg:
    name: str
    capability: Capability
    evidence: Evidence
    source: Source
    confidence: Confidence


def _strongest(
    context: AnalysisContext,
    capabilities: frozenset[Capability],
    label: str,
    *,
    exclude: frozenset[tuple[str, int | None]] = frozenset(),
) -> _Leg | None:
    """Pick the best-evidenced observation satisfying one leg of a combination.

    ``exclude`` holds sightings already used for another leg, so one line of code
    cannot satisfy two legs of the same combination.
    """
    best: _Leg | None = None
    for observation in context.capabilities.observations:
        if observation.capability not in capabilities:
            continue
        if observation.source.is_claim:
            continue  # a claim is not evidence of behaviour
        if (observation.evidence.path, observation.evidence.line) in exclude:
            continue
        candidate = _Leg(
            name=label,
            capability=observation.capability,
            evidence=Evidence(
                path=observation.evidence.path,
                line=observation.evidence.line,
                excerpt=observation.evidence.excerpt,
                decode_chain=observation.evidence.decode_chain,
                note=f"{label}: {observation.detail}",
            ),
            source=observation.source,
            confidence=observation.confidence,
        )
        if best is None or candidate.confidence.rank < best.confidence.rank:
            best = candidate
    return best


def _combined_confidence(*legs: _Leg) -> Confidence:
    """A combination is only as certain as its weakest leg."""
    worst = max(leg.confidence.rank for leg in legs)
    return {0: Confidence.HIGH, 1: Confidence.MEDIUM, 2: Confidence.LOW}[worst]


@registry.implement("CON010")
def check_lethal_trifecta(context: AnalysisContext) -> Iterator[Finding]:
    actual = context.capabilities.actual
    if not (actual & PRIVATE_DATA and actual & UNTRUSTED_INPUT and actual & EXTERNAL_COMMS):
        return

    private = _strongest(context, PRIVATE_DATA, "private data access")
    if private is None:
        return
    used: frozenset[tuple[str, int | None]] = frozenset(
        {(private.evidence.path, private.evidence.line)}
    )
    external = _strongest(context, EXTERNAL_COMMS, "external communication", exclude=used)
    if external is None:
        return
    used |= {(external.evidence.path, external.evidence.line)}
    # The untrusted-input leg must be a different sighting from the egress leg:
    # one network call is not both the way data comes in and the way it leaves.
    untrusted = _strongest(context, UNTRUSTED_INPUT, "untrusted external input", exclude=used)
    if untrusted is None:
        return

    # FS_READ alone is too weak a "private data" leg to justify HIGH severity:
    # nearly every skill reads files. Require a stronger data source for that.
    strong_data = bool(actual & (PRIVATE_DATA - {Capability.FS_READ}))
    severity = Severity.HIGH if strong_data else Severity.MEDIUM

    yield emit(
        "CON010",
        context.name,
        message=(
            f"all three legs present — {private.capability.label}, "
            f"{untrusted.capability.label}, {external.capability.label}"
        ),
        evidence=[private.evidence, untrusted.evidence, external.evidence],
        severity=severity,
        confidence=_combined_confidence(private, untrusted, external),
        related=["EXF001", "EXF002", "INJ001"],
    )


def _pair_rule(
    rule_id: str,
    left: frozenset[Capability],
    left_label: str,
    right: frozenset[Capability],
    right_label: str,
    *,
    severity: Severity | None = None,
):
    def check(context: AnalysisContext) -> Iterator[Finding]:
        actual = context.capabilities.actual
        if not (actual & left and actual & right):
            return
        first = _strongest(context, left, left_label)
        second = _strongest(context, right, right_label)
        if not (first and second):
            return
        if first.evidence.path == second.evidence.path and first.evidence.line == second.evidence.line:
            return  # the same sighting cannot satisfy both legs
        yield emit(
            rule_id,
            context.name,
            message=f"{first.capability.label} and {second.capability.label} in the same skill",
            evidence=[first.evidence, second.evidence],
            severity=severity,
            confidence=_combined_confidence(first, second),
        )

    return check


registry.implement("CON011")(
    _pair_rule(
        "CON011",
        frozenset({Capability.SECRET_ACCESS, Capability.CREDENTIAL_HANDLING, Capability.ENV_READ}),
        "credential access",
        frozenset({Capability.NET_OUTBOUND}),
        "network egress",
    )
)

registry.implement("CON012")(
    _pair_rule(
        "CON012",
        frozenset({Capability.REMOTE_INSTRUCTIONS, Capability.NET_FETCH}),
        "untrusted remote content",
        frozenset({Capability.SHELL_EXEC, Capability.CODE_EVAL}),
        "shell or code execution",
    )
)

registry.implement("CON013")(
    _pair_rule(
        "CON013",
        frozenset({Capability.PKG_INSTALL, Capability.REMOTE_INSTRUCTIONS}),
        "mutable dependency",
        frozenset({Capability.SHELL_EXEC, Capability.PROC_EXEC, Capability.CODE_EVAL}),
        "privileged execution",
    )
)

registry.implement("CON014")(
    _pair_rule(
        "CON014",
        frozenset({Capability.PERSISTENCE, Capability.CONFIG_MODIFY, Capability.MEMORY_WRITE}),
        "persistence",
        frozenset(
            {
                Capability.SHELL_EXEC,
                Capability.NET_OUTBOUND,
                Capability.NET_FETCH,
                Capability.SECRET_ACCESS,
                Capability.CODE_EVAL,
            }
        ),
        "privileged capability",
    )
)
