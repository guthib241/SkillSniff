"""Authoring quality rules (QUA family).

These implement the skill-smell taxonomy from Hong, Imani & Ahmed, "From Anatomy
to Smells: An Empirical Study of SKILL.md in Agent Skills" (arXiv:2607.01456),
which analysed 238 real-world skills and found that over 99% carry at least one
smell.

Two deliberate design choices:

*Quality is not security.* Findings in this family never contribute to the
security verdict. A beautifully documented skill that exfiltrates credentials
must not look better than a scruffy one that does nothing wrong, and the
previous single-score design allowed exactly that.

*Every rule is deterministic.* The source paper detects 5 of its 26 smells
statically and the remaining 21 with a language model. Every rule here runs
without an API key or a network call, which is what allows the gate to run on
every pull request. That trades recall for availability, and where a smell
cannot be reduced to a reliable signal it is documented as out of scope rather
than guessed at. Each rule's ``limitations`` states the proxy it uses.

The original rule identifiers from that taxonomy are preserved in each rule's
``taxonomy`` field so findings remain cross-referenceable.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillsniff.analysis.context import AnalysisContext
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity
from skillsniff.rules.base import Family, RuleMeta, emit, registry

PAPER = "https://arxiv.org/abs/2607.01456"

MAX_BODY_WORDS = 5000
MAX_BODY_LINES = 500
DELEGATION_THRESHOLD = 1500

VAGUE_NAMES = frozenset(
    {
        "dig", "run", "do", "go", "helper", "utils", "util", "tools", "tool",
        "main", "core", "misc", "stuff", "handler", "manager", "assistant",
        "agent", "skill", "common", "general", "base", "app", "code", "work",
        "test", "temp", "new", "my-skill", "example", "demo", "thing",
    }
)

VALIDATION_SIGNALS = (
    "verify", "validate", "check that", "confirm", "run the test", "assert",
    "sanity", "double-check", "inspect the output", "before finishing",
    "before you finish", "definition of done", "self-check", "re-read",
    "make sure", "ensure that", "cross-check", "re-run",
)

GUARDRAIL_SIGNALS = (
    "do not", "don't", "never", "avoid", "must not", "refuse", "stop and",
    "abort", "under no circumstances", "out of scope", "not for", "do no",
    "should not", "cannot", "reject",
)

NON_NEGOTIABLE_SIGNALS = (
    "do not skip", "never skip", "non-negotiable", "mandatory", "required step",
    "always run", "no exceptions", "even if", "do not rationalize",
    "do not rationalise", "must complete", "be skipped", "skipping",
    "do not shortcut", "regardless of", "exempt", "not optional",
    "without exception", "under no circumstances", "no matter how",
)

HUMAN_LOOP_SIGNALS = (
    "ask the user", "ask the human", "confirm with the user", "check with the",
    "prompt the user", "request confirmation", "stop and ask", "surface to the",
    "escalate", "get approval", "ask before", "clarify with", "ask for",
)

PROGRESS_SIGNALS = (
    "- [ ]", "checklist", "track progress", "todo", "mark each",
    "keep a running", "progress", "tick off", "as you complete",
)

CAVEAT_SIGNALS = (
    "caveat", "gotcha", "pitfall", "common mistake", "known issue", "watch out",
    "beware", "limitation", "edge case", "failure mode", "if this fails",
    "troubleshoot", "when this breaks", "does not", "cannot detect",
)

OUTPUT_FORMAT_SIGNALS = (
    "output format", "format the output", "return a", "respond with", "produce a",
    "the report should", "structure the", "deliverable", "output should", "emit a",
)

WARNING_WORDS = ("warning", "caution", "danger", "critical", "important", "note that")
CALLOUT_MARKERS = ("**", "> ", "⚠", "##", "!!!", "[!", "`", "__")

FIRST_PERSON = re.compile(r"\b(?:I|I'm|I'll|my|we|we're|our|us)\b")
SECOND_PERSON = re.compile(r"\b(?:you|your|you're|yourself)\b", re.IGNORECASE)
XML_TAG = re.compile(r"<[a-zA-Z_][\w:-]*\s*(?:/?>|\s[^>]*>)")
BACKSLASH_PATH = re.compile(r"[A-Za-z0-9_.\-]\\[A-Za-z0-9_.\-]+\\")
ORDERED_ITEM = re.compile(r"^\s*\d+[.)]\s+\S", re.MULTILINE)
STEP_HEADING = re.compile(r"^\s*(?:\d+[.)]\s+|#{2,}\s*step\s|#{2,}\s*\d+[.)]?\s)", re.IGNORECASE | re.MULTILINE)
CODE_FENCE = re.compile(r"```")
TIME_SENSITIVE = re.compile(
    r"\b(?:as of (?:january|february|march|april|may|june|july|august|september|"
    r"october|november|december|20\d\d)|currently the latest|latest version is|"
    r"current version is|as of today|at the time of writing|this year|next year|last month)\b",
    re.IGNORECASE,
)


def _meta(rule_id: str, title: str, severity: Severity, confidence: Confidence,
          explanation: str, impact: str, remediation: str, limitations: str,
          taxonomy: tuple[str, ...]) -> RuleMeta:
    return RuleMeta(
        id=rule_id, title=title, family=Family.QUA, severity=severity,
        confidence=confidence, explanation=explanation, impact=impact,
        remediation=remediation, limitations=limitations,
        references=(PAPER,), taxonomy=taxonomy,
    )


registry.define_all(
    [
        _meta("QUA001", "Skill body is too long", Severity.MEDIUM, Confidence.HIGH,
              f"The body exceeds {MAX_BODY_WORDS} words or {MAX_BODY_LINES} lines.",
              "The entire body loads into context every time the skill triggers, displacing the "
              "user's actual task and degrading the agent's attention across it.",
              "Move detail into references/ files the agent loads only when needed.",
              "A word count is a proxy for context cost, not a measure of whether the content earns its place.",
              ("LSB",)),
        _meta("QUA002", "Detail not delegated to reference files", Severity.LOW, Confidence.MEDIUM,
              f"The body exceeds {DELEGATION_THRESHOLD} words with no references/ directory.",
              "Low-level detail is loaded unconditionally instead of on demand.",
              "Move detail into references/ and link to it from the body.",
              "Some long skills legitimately have no separable detail.",
              ("UD",)),
        _meta("QUA003", "Description does not convey a capability", Severity.MEDIUM, Confidence.HIGH,
              "The skill's name is a generic word such as 'helper', 'utils', or 'run'.",
              "The agent routes to skills by name and description. A name conveying no capability "
              "cannot be matched to a task, so the skill is never selected.",
              "Name the action and the object, e.g. 'threat-model-review'.",
              "Uses a fixed list of generic names; an unusual but equally vague name is not caught.",
              ("USN",)),
        _meta("QUA004", "Description is not in the third person", Severity.LOW, Confidence.MEDIUM,
              "The description uses first or second person outside quoted trigger phrases.",
              "Mixed point of view hurts retrieval, because descriptions are matched against "
              "task statements written in the third person.",
              "Write 'Reviews X and reports Y', not 'I review X' or 'You can use this to'.",
              "Quoted spans are excluded, since a quoted user utterance is correctly first-person.",
              ("NTPD",)),
        _meta("QUA005", "XML-style tags in the description", Severity.MEDIUM, Confidence.HIGH,
              "The frontmatter description contains XML-style tags such as <note> or "
              "<important>. The description is concatenated into the agent's context during "
              "skill selection, so markup there is interpreted rather than displayed.",
              "Description text is injected into the agent's prompt during skill selection; "
              "markup there is a known injection vector. INJ006 covers the malicious case, this "
              "rule the merely careless one.",
              "Remove the tags and write plain prose.",
              "A skill legitimately about XML will match.",
              ("XID",)),
        _meta("QUA006", "Workflow has no ordered steps", Severity.MEDIUM, Confidence.MEDIUM,
              "A body over 250 words describes a procedure as prose with no numbered steps.",
              "The agent cannot track its position in an unordered procedure, and the author "
              "cannot tell where it went wrong.",
              "Decompose the procedure into numbered steps.",
              "Reference material that is not a procedure will match; consider suppressing per path.",
              ("TSW",)),
        _meta("QUA007", "No validation step", Severity.MEDIUM, Confidence.MEDIUM,
              "The body contains no instruction to verify the work before declaring it done.",
              "One-shot generation with no feedback loop is the most common cause of confidently "
              "wrong output.",
              "Add an explicit check the agent must run before finishing.",
              "Detects validation *vocabulary*. Deliberately excludes bare 'review' and 'test', "
              "which are domain nouns in review and testing skills and would produce false "
              "negatives on exactly the skills that most need this rule.",
              ("NVS",)),
        _meta("QUA008", "No mechanism to ask the user", Severity.LOW, Confidence.MEDIUM,
              "The body never tells the agent when to stop and ask rather than assume.",
              "The agent guesses at ambiguity instead of resolving it, and the user finds out "
              "after the work is done.",
              "State the conditions under which the agent should stop and ask.",
              "Lexical proxy; a skill may express this in unrecognised phrasing.",
              ("NAH",)),
        _meta("QUA009", "Nothing prevents skipping a required step", Severity.MEDIUM, Confidence.MEDIUM,
              "No language marks any step as non-skippable.",
              "Agents rationalise their way out of steps that are merely listed. The source study "
              "found this the most common smell in the wild.",
              "Mark the steps that must not be skipped and say so explicitly.",
              "Presence of the phrasing does not guarantee the agent honours it.",
              ("RL",)),
        _meta("QUA010", "No progress tracking for a long procedure", Severity.LOW, Confidence.MEDIUM,
              "Five or more steps with no checklist or progress mechanism.",
              "Long procedures drift without a way for the agent to mark position.",
              "Give the agent a checklist to mark off.",
              "Counts ordered list items, which under-counts procedures written as headings.",
              ("NPT",)),
        _meta("QUA011", "No guardrails", Severity.MEDIUM, Confidence.MEDIUM,
              "The body never states what the skill should not do.",
              "Without stated limits the agent applies the skill outside its competence and "
              "produces confident output in situations the author never considered.",
              "State the out-of-scope cases and what to do when the task is inappropriate.",
              "Lexical proxy for the presence of constraints.",
              ("NG",)),
        _meta("QUA012", "No caveats or failure modes documented", Severity.LOW, Confidence.MEDIUM,
              "The body documents no gotchas, limitations, or failure modes.",
              "The agent has no way to recognise that the situation is one the skill handles badly.",
              "Document what commonly goes wrong and how to resolve it.",
              "Lexical proxy.",
              ("MC",)),
        _meta("QUA013", "Warning text is not visually marked", Severity.LOW, Confidence.LOW,
              "A line containing warning vocabulary carries no bold, blockquote, heading, or "
              "code formatting.",
              "Unmarked warnings are skimmed past by both humans and models.",
              "Put warnings in a bold line, a blockquote, or their own heading.",
              "Formatting is a weak proxy for salience.",
              ("BG",)),
        _meta("QUA014", "No worked example", Severity.MEDIUM, Confidence.MEDIUM,
              "The body contains neither the word 'example' nor a fenced code block.",
              "Examples are the highest-leverage content in a skill; without one the agent "
              "infers the expected shape of the work from the prose alone.",
              "Include at least one concrete input/output pair.",
              "Presence of a code fence is taken as evidence of an example, which over-counts.",
              ("ME",)),
        _meta("QUA015", "Time-sensitive content", Severity.LOW, Confidence.MEDIUM,
              "The body contains statements pinned to a moment in time.",
              "The content silently becomes wrong, and neither agent nor user can tell when.",
              "Remove the time-pinned statement, or move it to a reference file with a review date.",
              "Matches a fixed set of phrasings.",
              ("TSS",)),
        _meta("QUA016", "Output format described but not shown", Severity.LOW, Confidence.MEDIUM,
              "The body describes an output format without giving a template.",
              "The agent invents a format, and output varies between runs.",
              "Show the exact shape of the expected output in a fenced block.",
              "Lexical proxy.",
              ("MT",)),
        _meta("QUA017", "File paths use backslashes", Severity.LOW, Confidence.HIGH,
              "Paths in the body use Windows-style backslash separators.",
              "Agents traverse the skill directory as a POSIX filesystem; backslash paths do not "
              "resolve.",
              "Rewrite the paths with forward slashes, which resolve on every platform the "
              "agent runs on.",
              "An escaped character in prose can match.",
              ("BP",)),
        _meta("QUA018", "No explicit usage rules", Severity.LOW, Confidence.LOW,
              "The body has no section stating rules, constraints, or principles.",
              "The agent has no stated standard to hold itself to.",
              "Add a short rules section stating the non-negotiable constraints.",
              "Weak structural proxy; many good skills express rules without a dedicated heading.",
              ("MUR",)),
    ]
)


def _contains_any(haystack: str, needles: tuple[str, ...]) -> bool:
    lowered = haystack.lower()
    return any(needle in lowered for needle in needles)


@registry.implement(*[f"QUA{i:03d}" for i in range(1, 19)])
def check_quality(context: AnalysisContext) -> Iterator[Finding]:
    skill = context.skill
    if not skill.frontmatter.present or not skill.frontmatter.ok:
        return  # spec rules already reported the structural problem

    body = skill.body
    name = context.name
    description = skill.description
    entry = context.entry_path
    offset = skill.frontmatter.body_start_line - 1

    def body_evidence(line: int | None = None, excerpt: str = "") -> list[Evidence]:
        return [Evidence(path=entry, line=(line + offset) if line else None, excerpt=excerpt)]

    # -- size ---------------------------------------------------------------
    if skill.body_words > MAX_BODY_WORDS:
        yield emit("QUA001", name,
                   message=f"body is {skill.body_words} words (ceiling {MAX_BODY_WORDS})",
                   evidence=body_evidence(1))
    elif skill.body_lines > MAX_BODY_LINES:
        yield emit("QUA001", name,
                   message=f"body is {skill.body_lines} lines (recommended ceiling {MAX_BODY_LINES})",
                   evidence=body_evidence(1), severity=Severity.LOW)

    if skill.body_words > DELEGATION_THRESHOLD and not skill.has_dir("references"):
        yield emit("QUA002", name,
                   message=f"body is {skill.body_words} words with no references/ directory",
                   evidence=body_evidence(1))

    # -- naming and description --------------------------------------------
    if skill.name and skill.name.lower() in VAGUE_NAMES:
        yield emit("QUA003", name, message=f"name {skill.name!r} does not convey a capability",
                   evidence=[context.frontmatter_evidence("name", skill.name)])

    if description:
        if XML_TAG.search(description):
            yield emit("QUA005", name, message="description contains XML-style tags",
                       evidence=[context.frontmatter_evidence("description", description[:120])])

        # Quoted spans are trigger phrases the *user* would type, so first and
        # second person inside them is correct authoring, not a defect.
        unquoted = re.sub(r"[\"'“‘][^\"'”’]{0,160}[\"'”’]", " ", description)
        if FIRST_PERSON.search(unquoted) or SECOND_PERSON.search(unquoted):
            yield emit("QUA004", name, message="description is not written in the third person",
                       evidence=[context.frontmatter_evidence("description", description[:120])])

    # -- structure ----------------------------------------------------------
    ordered = ORDERED_ITEM.findall(body)
    has_steps = bool(STEP_HEADING.search(body)) or len(ordered) >= 2
    if skill.body_words > 250 and not has_steps:
        yield emit("QUA006", name, message="workflow is prose with no numbered steps or step headings",
                   evidence=body_evidence(1))

    if len(ordered) >= 5 and not _contains_any(body, PROGRESS_SIGNALS):
        yield emit("QUA010", name, message=f"{len(ordered)} steps with no progress-tracking mechanism",
                   evidence=body_evidence(1))

    # -- required content ---------------------------------------------------
    checks = (
        ("QUA007", VALIDATION_SIGNALS, "no validation or verification step"),
        ("QUA008", HUMAN_LOOP_SIGNALS, "no mechanism for the agent to ask the user"),
        ("QUA009", NON_NEGOTIABLE_SIGNALS, "nothing prevents the agent from skipping a required step"),
        ("QUA011", GUARDRAIL_SIGNALS, "no guardrails constraining what the skill should not do"),
        ("QUA012", CAVEAT_SIGNALS, "no caveats, gotchas or failure modes documented"),
    )
    for rule_id, signals, message in checks:
        if not _contains_any(body, signals):
            yield emit(rule_id, name, message=message, evidence=body_evidence(1))

    if "example" not in body.lower() and not CODE_FENCE.search(body):
        yield emit("QUA014", name, message="no worked example or code block", evidence=body_evidence(1))

    # -- formatting ---------------------------------------------------------
    for index, line in enumerate(body.splitlines(), start=1):
        stripped = line.strip()
        lowered = stripped.lower()
        if any(word in lowered for word in WARNING_WORDS) and not any(
            marker in stripped for marker in CALLOUT_MARKERS
        ):
            yield emit("QUA013", name,
                       message=f"warning text is not visually marked: {stripped[:60]!r}",
                       evidence=body_evidence(index, stripped[:120]))
            break

    match = TIME_SENSITIVE.search(body)
    if match:
        yield emit("QUA015", name, message=f"content will go stale: {match.group(0)!r}",
                   evidence=body_evidence(body.count("\n", 0, match.start()) + 1, match.group(0)))

    if _contains_any(body, OUTPUT_FORMAT_SIGNALS) and not CODE_FENCE.search(body):
        yield emit("QUA016", name, message="an output format is described but no template is given",
                   evidence=body_evidence(1))

    backslash = BACKSLASH_PATH.search(body)
    if backslash:
        yield emit("QUA017", name, message="file paths use backslashes",
                   evidence=body_evidence(body.count("\n", 0, backslash.start()) + 1, backslash.group(0)))

    has_rules_heading = re.search(
        r"^#{2,}\s.*\b(?:rule|constraint|principle|polic|standard|requirement|guardrail)",
        body, re.IGNORECASE | re.MULTILINE,
    )
    if not has_rules_heading and not _contains_any(body, ("rules:", "you must", "always ", "must always")):
        yield emit("QUA018", name, message="no explicit rules governing how the skill is used",
                   evidence=body_evidence(1))
