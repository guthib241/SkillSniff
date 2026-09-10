"""Capability contract rules (CON family).

These rules compare what a skill *says* against what it *does*. That comparison
is the product's central question, and it is only possible because capability
observations retain their source: description and declared tools on one side,
instructions, code, dependencies and external references on the other.

Severity scales with the privilege of the gap, not its size. A documentation
skill that also reads files is unremarkable; a documentation skill that also
executes shell commands and makes network requests is not.
"""

from __future__ import annotations

from collections.abc import Iterator

from skillsniff.analysis.context import AnalysisContext
from skillsniff.model.capability import Capability, Source
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity
from skillsniff.rules.base import Family, RuleMeta, emit, registry

#: Capabilities whose appearance without any declaration is worth a finding on
#: its own. Reading files is ubiquitous and not on this list.
_NOTABLE_UNDECLARED = frozenset(
    {
        Capability.SHELL_EXEC,
        Capability.PROC_EXEC,
        Capability.CODE_EVAL,
        Capability.NET_OUTBOUND,
        Capability.NET_FETCH,
        Capability.SECRET_ACCESS,
        Capability.CREDENTIAL_HANDLING,
        Capability.ENV_READ,
        Capability.PKG_INSTALL,
        Capability.REMOTE_INSTRUCTIONS,
        Capability.FS_DELETE,
        Capability.PERSISTENCE,
        Capability.CONFIG_MODIFY,
        Capability.MEMORY_WRITE,
    }
)

registry.define_all(
    [
        RuleMeta(
            id="CON001",
            title="Capability mismatch between description and behaviour",
            family=Family.CON,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill exercises privileged capabilities that its description and declared "
                "tools do not account for. Capabilities are inferred separately from the "
                "description, the 'allowed-tools' list, the instruction body, bundled code, "
                "dependency manifests, and external references, then compared."
            ),
            impact=(
                "The user consented to what the description said. Every capability beyond that "
                "is reach they did not agree to, and it is the shape most commonly seen in "
                "skills that are functional on the surface and malicious underneath."
            ),
            remediation=(
                "Either narrow the implementation to what the description promises, or update "
                "the description and 'allowed-tools' to state the full surface honestly."
            ),
            limitations=(
                "Capability inference from prose is approximate. A skill can legitimately imply "
                "a capability in wording this tool does not recognise, so review the evidence "
                "before treating a mismatch as intent."
            ),
            taxonomy=("LLM06:ExcessiveAgency",),
        ),
        RuleMeta(
            id="CON002",
            title="Undeclared privileged capability",
            family=Family.CON,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A privileged capability is evidenced in the skill's behaviour but appears in "
                "no claim the skill makes about itself."
            ),
            impact=(
                "A reviewer reading the frontmatter does not learn that the skill can do this. "
                "Policy engines that gate on declarations will not gate on it either."
            ),
            remediation="Declare the capability in 'allowed-tools' or describe it in the description.",
            taxonomy=("LLM06:ExcessiveAgency",),
        ),
        RuleMeta(
            id="CON003",
            title="Declared capability never used",
            family=Family.CON,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            explanation=(
                "The skill declares a tool granting a privileged capability that no instruction, "
                "script, or dependency appears to use."
            ),
            impact=(
                "Unused permissions widen the blast radius for no benefit. If the skill is "
                "later compromised, the attacker inherits the grant."
            ),
            remediation="Remove the unused entry from 'allowed-tools'.",
            limitations=(
                "Static analysis cannot see every use. A capability exercised only through "
                "prose this tool does not parse will appear unused."
            ),
            taxonomy=("LLM06:ExcessiveAgency",),
        ),
        RuleMeta(
            id="CON004",
            title="Broad capability surface for a narrow stated purpose",
            family=Family.CON,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill describes a narrow, local task but exercises three or more distinct "
                "privileged capability groups."
            ),
            limitations=(
                "'Narrow purpose' is inferred from description length and capability breadth, "
                "both crude proxies. A terse description on a genuinely broad tool will "
                "match."
            ),
            impact=(
                "The gap between stated purpose and actual reach is the practical definition of "
                "excessive privilege."
            ),
            remediation="Split the skill, or narrow its implementation to its stated purpose.",
            taxonomy=("LLM06:ExcessiveAgency",),
        ),
    ]
)


def _evidence_for(context: AnalysisContext, capability: Capability, limit: int = 3) -> list[Evidence]:
    observations = [
        o
        for o in context.capabilities.by_capability(capability)
        if not o.source.is_claim
    ]
    observations.sort(key=lambda o: o.confidence.rank)
    return [
        Evidence(
            path=o.evidence.path,
            line=o.evidence.line,
            excerpt=o.evidence.excerpt,
            decode_chain=o.evidence.decode_chain,
            note=f"{o.source.value}: {o.detail}",
        )
        for o in observations[:limit]
    ]


@registry.implement("CON001", "CON002", "CON004")
def check_capability_mismatch(context: AnalysisContext) -> Iterator[Finding]:
    surface = context.capabilities
    description = context.skill.description
    if not description and not context.skill.declared_tools:
        return  # nothing was claimed, so nothing can be mismatched

    undeclared = {c for c in surface.undeclared if c in _NOTABLE_UNDECLARED}
    if not undeclared:
        return

    privileged_undeclared = sorted(undeclared, key=lambda c: c.value)
    groups = {c.group for c in surface.actual if c.is_privileged}

    # CON001: several undeclared privileged capabilities is a contract mismatch.
    if len(privileged_undeclared) >= 2:
        evidence: list[Evidence] = []
        for capability in privileged_undeclared[:4]:
            evidence.extend(_evidence_for(context, capability, limit=1))
        yield emit(
            "CON001",
            context.name,
            message=(
                "described as "
                f"{description[:70]!r}" if description else "no description"
            )
            + " but also "
            + ", ".join(c.label for c in privileged_undeclared[:5]),
            evidence=[
                context.frontmatter_evidence("description", description[:120]),
                *evidence,
            ],
            confidence=Confidence.MEDIUM if len(privileged_undeclared) >= 3 else Confidence.LOW,
        )
    else:
        for capability in privileged_undeclared:
            yield emit(
                "CON002",
                context.name,
                message=f"can {capability.label} but does not declare it",
                evidence=_evidence_for(context, capability) or [context.entry_evidence()],
            )

    if len(groups) >= 3 and len(description.split()) < 40:
        yield emit(
            "CON004",
            context.name,
            message=(
                f"description is {len(description.split())} words but the skill exercises "
                f"{len(groups)} privileged capability groups: {', '.join(sorted(groups))}"
            ),
            evidence=[
                context.frontmatter_evidence("description", description[:120]),
                *[e for c in sorted(surface.privileged, key=lambda c: c.value)[:3] for e in _evidence_for(context, c, 1)],
            ],
        )


@registry.implement("CON003")
def check_unused_capability(context: AnalysisContext) -> Iterator[Finding]:
    surface = context.capabilities
    declared_only = surface.by_source(Source.DECLARED) - surface.actual
    for capability in sorted(declared_only, key=lambda c: c.value):
        if not capability.is_privileged:
            continue
        observations = [o for o in surface.by_capability(capability) if o.source is Source.DECLARED]
        yield emit(
            "CON003",
            context.name,
            message=f"declares the ability to {capability.label}, but no use was found",
            evidence=[o.evidence for o in observations[:2]],
        )
