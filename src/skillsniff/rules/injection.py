"""Prompt and instruction injection rules (INJ family).

Skill text is not documentation. It is loaded into the agent's context and read
as instruction, so text that tries to override the agent's operating rules, hide
actions from the user, or smuggle directives through a channel a reviewer cannot
see is an attack on the agent rather than a documentation defect.

All patterns run against the raw text, the Unicode-normalised text, and every
decoded region, so an injection hidden behind a zero-width space or a base64
blob is caught by the same rule that catches the plain version.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillsniff.analysis.context import AnalysisContext
from skillsniff.model.finding import Confidence, Finding, Severity
from skillsniff.rules import _scan
from skillsniff.rules.base import Family, RuleMeta, emit, registry

OWASP = "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
TOXICSKILLS = "https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/"

INSTRUCTION_OVERRIDE = re.compile(
    r"(?:ignore|disregard|forget|discard|override|bypass|skip)\s+"
    r"(?:all\s+|any\s+|the\s+|your\s+|these\s+)*"
    r"(?:previous|prior|above|earlier|preceding|foregoing|system|initial|original|other)?\s*"
    r"(?:instruction|prompt|rule|guideline|directive|constraint|polic|restriction|guardrail|safety)",
    re.IGNORECASE,
)

ROLE_HIJACK = re.compile(
    r"you\s+are\s+(?:now\s+)?(?:in\s+)?(?:a\s+)?"
    r"(?:developer|god|admin|root|unrestricted|jailbroken|dan|do\s+anything\s+now|evil|uncensored)"
    r"\s*(?:mode|assistant|ai|model)?"
    r"|enter\s+(?:developer|debug|god|unrestricted)\s+mode"
    r"|act\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored|jailbroken|amoral)"
    r"|from\s+now\s+on[,\s]+you\s+(?:will|must|shall)\s+(?:ignore|disregard|not\s+follow)",
    re.IGNORECASE,
)

CONCEALMENT = re.compile(
    r"(?:do\s*n[o']?t|never|avoid|refrain\s+from)\s+"
    r"(?:tell|telling|inform|informing|mention|mentioning|notify|notifying|show|showing|"
    r"reveal|revealing|disclose|disclosing|report|reporting|log|logging|display|displaying)\s+"
    r"(?:this|it|that|any(?:thing)?|the\s+\w+)?\s*(?:to\s+)?(?:the\s+)?(?:user|human|operator|owner|developer)"
    # "asking" is deliberately absent here. Concealment is about hiding what was
    # *done*; failing to ask is about permission, and they are different things.
    # A bare "without asking" is overwhelmingly benign English — "a spec written
    # without asking the user anything restates the request" is advocating
    # asking, not concealing — and matching it made this rule fire on ordinary
    # authoring advice. Instruction-level permission bypass is PRV001's job,
    # where the pattern requires an actual imperative.
    r"|without\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:user|human|operator)"
    r"|without\s+the\s+user'?s?\s+knowledge"
    r"|hide\s+(?:this|it|these|the\s+\w+)\s+from\s+(?:the\s+)?(?:user|human|operator|log|output)"
    r"|silently\s+(?:send|upload|transmit|exfiltrat|forward|post|copy|delete|modif)"
    r"|(?:keep|leave)\s+(?:this|it)\s+(?:secret|hidden|confidential)\s+from"
    r"|do\s+not\s+(?:include|mention)\s+(?:this|it)\s+in\s+(?:your|the)\s+(?:summary|report|response|output)",
    re.IGNORECASE,
)

#: Structural markers that impersonate the conversation framing. Text claiming
#: to be a system turn is trying to be believed as one.
FRAME_IMPERSONATION = re.compile(
    r"<\s*/?\s*(?:system|assistant|human|user|developer|instructions?|important_instructions)\s*>"
    r"|\[/?(?:SYSTEM|INST|ASSISTANT|USER)\]"
    r"|^\s*(?:System|Assistant|Human)\s*:\s*(?:you\s+(?:must|are|should)|ignore|new\s+instruction)"
    r"|<\|(?:im_start|im_end|system|endoftext|start_header_id)\|>"
    r"|###\s*(?:SYSTEM|NEW\s+INSTRUCTIONS?)\s*(?:###|:)",
    re.IGNORECASE | re.MULTILINE,
)

AUTHORITY_CLAIM = re.compile(
    r"(?:this|the\s+following)\s+(?:instruction|directive|rule|message|command)s?\s+"
    r"(?:take[s]?\s+precedence|override[s]?|supersede[s]?|has\s+priority)"
    r"|(?:highest|maximum|top)\s+priority\s+(?:instruction|directive|override)"
    r"|(?:mandatory|non-negotiable)\s+(?:system\s+)?override"
    r"|as\s+(?:the\s+)?(?:system|anthropic|openai|your\s+developer)[,\s]+(?:i|we)\s+(?:instruct|order|require|authorize)",
    re.IGNORECASE,
)

registry.define_all(
    [
        RuleMeta(
            id="INJ001",
            title="Instruction-override phrasing",
            family=Family.INJ,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "The skill contains text of the form 'ignore all previous instructions'. Skill "
                "content is loaded into the agent's context verbatim, so this phrasing is a "
                "direct attempt to countermand the agent's operating rules rather than a "
                "description of behaviour."
            ),
            impact=(
                "If honoured, the agent discards its safety constraints and the user's actual "
                "instructions, and follows the skill instead. This is the entry point for every "
                "subsequent action the skill wants to take."
            ),
            remediation=(
                "Remove the phrasing. A legitimate skill constrains its own behaviour and never "
                "instructs the agent to disregard anything outside itself. If the text is a "
                "quoted example of an attack, move it into a fenced code block and label it."
            ),
            limitations=(
                "Matches English phrasing. Injection written in another language, or paraphrased "
                "to avoid these verbs, is not detected by this rule."
            ),
            references=(OWASP, TOXICSKILLS),
            taxonomy=("LLM01:PromptInjection",),
        ),
        RuleMeta(
            id="INJ002",
            title="Role or persona hijack",
            family=Family.INJ,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "The skill tells the agent it is now operating as an unrestricted persona — "
                "'developer mode', 'DAN', 'jailbroken', 'act as an uncensored assistant'."
            ),
            limitations=(
                "Matches English persona-reassignment phrasing. A hijack written in another "
                "language, or phrased indirectly, is not detected."
            ),
            impact=(
                "Persona reassignment is used to detach the agent from its safety training so "
                "that later instructions in the same skill are followed without objection."
            ),
            remediation="Remove the persona reassignment. A skill scopes a task; it does not redefine the agent.",
            references=(OWASP,),
            taxonomy=("LLM01:PromptInjection",),
        ),
        RuleMeta(
            id="INJ003",
            title="Instruction to conceal actions from the user",
            family=Family.INJ,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "The skill instructs the agent to perform an action without telling the user, "
                "to hide something from output or logs, or to act 'silently'."
            ),
            impact=(
                "Concealment removes the human's ability to notice and stop the action. It is "
                "the defining property of a malicious skill: there is no legitimate reason to "
                "withhold an action from the person on whose behalf it is taken."
            ),
            remediation=(
                "Remove the concealment instruction. If the intent is to keep output concise, "
                "say so in terms of formatting rather than in terms of what the user is told."
            ),
            limitations=(
                "Phrasings like 'keep the summary brief' are legitimate and not matched. The "
                "rule requires an explicit direction not to inform, reveal, or disclose."
            ),
            references=(TOXICSKILLS,),
            taxonomy=("LLM01:PromptInjection",),
        ),
        RuleMeta(
            id="INJ004",
            title="Conversation frame impersonation",
            family=Family.INJ,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The content contains markup that impersonates the structure of the "
                "conversation itself — '<system>' tags, '[INST]' markers, or chat template "
                "special tokens such as '<|im_start|>'."
            ),
            impact=(
                "Text that appears to come from a higher-trust turn can be treated as more "
                "authoritative than skill content, letting the skill escalate its own instructions."
            ),
            remediation=(
                "Remove the markup. If the skill legitimately needs to discuss these tokens, "
                "put them inside a fenced code block, which this rule treats as documentation."
            ),
            limitations=(
                "Generic XML in a skill about XML will match. Occurrences inside fenced code "
                "blocks are excluded to reduce that noise, so the rule can be evaded by a "
                "payload placed in a fence."
            ),
            references=(OWASP,),
            taxonomy=("LLM01:PromptInjection",),
        ),
        RuleMeta(
            id="INJ005",
            title="Claim of overriding authority",
            family=Family.INJ,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill asserts that its instructions take precedence over other "
                "instructions, or impersonates the model vendor or the user's developer to "
                "manufacture authority."
            ),
            limitations=(
                "Authority claims are matched lexically. A skill can assert precedence in "
                "phrasing this rule does not recognise."
            ),
            impact=(
                "Manufactured authority is used to make the agent prefer skill instructions "
                "over the user's, which inverts the trust relationship the user assumed."
            ),
            remediation="State scope without claiming precedence over the agent's other instructions.",
            references=(OWASP,),
            taxonomy=("LLM01:PromptInjection",),
        ),
        RuleMeta(
            id="INJ006",
            title="Injection payload hidden in the description",
            family=Family.INJ,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "The frontmatter description contains markup or instruction-override phrasing. "
                "The description is injected into the agent's context during skill *selection*, "
                "before the user has chosen to use the skill at all."
            ),
            limitations=(
                "Checks the description against the same patterns as the body rules, so it "
                "inherits their language and phrasing limits."
            ),
            impact=(
                "A payload here executes against every agent that merely lists available "
                "skills, without anyone invoking this one. It is the highest-reach position in "
                "the artifact."
            ),
            remediation="Keep the description to plain prose describing what the skill does and when to use it.",
            references=(TOXICSKILLS,),
            taxonomy=("LLM01:PromptInjection",),
        ),
    ]
)

_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)


def _mask_fences(text: str) -> str:
    """Blank out fenced code blocks, preserving offsets so lines stay correct."""
    return _FENCE_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


@registry.implement("INJ001", "INJ002", "INJ003", "INJ005")
def check_injection_text(context: AnalysisContext) -> Iterator[Finding]:
    rules = (
        ("INJ001", INSTRUCTION_OVERRIDE),
        ("INJ002", ROLE_HIJACK),
        ("INJ003", CONCEALMENT),
        ("INJ005", AUTHORITY_CLAIM),
    )
    for rule_id, pattern in rules:
        for match in _scan.scan(context, pattern, limit_per_file=5):
            yield _scan.emit_match(rule_id, context.name, match)


@registry.implement("INJ004")
def check_frame_impersonation(context: AnalysisContext) -> Iterator[Finding]:
    """Frame markup outside fenced code blocks only.

    Inside a fence the markup is being *shown*, not asserted, and a security
    skill that documents these tokens is the most likely thing to contain them.
    """
    for file in context.text_files():
        view = file.view
        if view is None:
            continue
        masked = _mask_fences(view.raw)
        for match in FRAME_IMPERSONATION.finditer(masked[: _scan.MAX_SCAN_BYTES]):
            line = masked.count("\n", 0, match.start()) + 1
            yield emit(
                "INJ004",
                context.name,
                message=f"{file.path}: conversation-frame markup {match.group(0).strip()!r}",
                evidence=[file.evidence(line=line, excerpt=match.group(0).strip()[:120])],
            )


@registry.implement("INJ006")
def check_description_injection(context: AnalysisContext) -> Iterator[Finding]:
    description = context.skill.description
    if not description:
        return

    from skillsniff.core.text import normalize

    projections = {"raw": description, "normalized": normalize(description)}
    reported: set[str] = set()

    for projection, text in projections.items():
        for label, pattern in (
            ("instruction override", INSTRUCTION_OVERRIDE),
            ("role hijack", ROLE_HIJACK),
            ("concealment", CONCEALMENT),
            ("frame markup", FRAME_IMPERSONATION),
            ("authority claim", AUTHORITY_CLAIM),
        ):
            match = pattern.search(text)
            if not match or label in reported:
                continue
            reported.add(label)
            note = "only visible after Unicode normalisation" if projection == "normalized" else ""
            evidence = context.frontmatter_evidence("description", match.group(0).strip()[:120])
            if note:
                from skillsniff.model.finding import Evidence

                evidence = Evidence(
                    path=evidence.path, line=evidence.line, excerpt=evidence.excerpt, note=note
                )
            yield emit(
                "INJ006",
                context.name,
                message=f"description contains {label}: {match.group(0).strip()[:80]!r}",
                evidence=[evidence],
            )
