"""Specification compliance rules.

A skill that violates the specification does not usually fail loudly — it is
silently ignored by the loader, which is why "my skill never triggers" is the
most common authoring complaint. These rules are about *correctness*, not
security, and their findings are deliberately kept out of the security verdict
so that a well-formed malicious skill cannot look good and a sloppy benign one
cannot look dangerous.

Where the specification is permissive, these rules are permissive. Flagging a
valid construct because the parser does not understand it would make the tool
actively harmful to correct skills.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillsniff.analysis.context import AnalysisContext
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity
from skillsniff.parse.frontmatter import IssueKind
from skillsniff.rules.base import Family, RuleMeta, emit, registry

#: The frontmatter keys the specification defines. Anything else belongs under
#: ``metadata``, which is the designated extension point.
ALLOWED_KEYS = frozenset({"name", "description", "license", "allowed-tools", "metadata", "compatibility"})

NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_NAME = 64
MAX_DESCRIPTION = 1024
MAX_COMPATIBILITY = 500

SPEC_URL = "https://agentskills.io/specification"

registry.define_all(
    [
        RuleMeta(
            id="SPEC001",
            title="Malformed or missing frontmatter",
            family=Family.SPEC,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "SKILL.md must open with a YAML frontmatter block delimited by '---' on the "
                "very first line. This rule reports a missing block, an unterminated block, "
                "content before the opening fence, invalid YAML, and a frontmatter block that "
                "is not a mapping."
            ),
            impact=(
                "Loaders that cannot parse the frontmatter skip the skill entirely. The skill "
                "appears installed but never activates, with no error shown to the user."
            ),
            remediation=(
                "Start the file with '---' at byte 0, close the block with '---', and ensure "
                "the contents parse as a YAML mapping of key/value pairs."
            ),
            limitations=(
                "Without PyYAML installed a small number of exotic YAML constructs are "
                "reported as unparseable lines rather than parsed. Install the 'yaml' extra "
                "for full fidelity."
            ),
            references=(SPEC_URL,),
        ),
        RuleMeta(
            id="SPEC002",
            title="Missing required field",
            family=Family.SPEC,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation="The specification requires both 'name' and 'description' in frontmatter.",
            impact=(
                "A skill with no name cannot be addressed; a skill with no description has no "
                "trigger condition and will never be selected by the agent."
            ),
            remediation="Add the missing field to the frontmatter block.",
            references=(SPEC_URL,),
        ),
        RuleMeta(
            id="SPEC003",
            title="Invalid name format",
            family=Family.SPEC,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "'name' must be lowercase letters, digits, and single interior hyphens: no "
                "uppercase, underscores, spaces, leading or trailing hyphens, or consecutive "
                "hyphens."
            ),
            impact="Loaders reject or mis-resolve names outside this grammar.",
            remediation="Rewrite the name as lowercase hyphen-separated words, e.g. 'threat-model-review'.",
            references=(SPEC_URL,),
        ),
        RuleMeta(
            id="SPEC004",
            title="Name does not match its directory",
            family=Family.SPEC,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            explanation=(
                "The 'name' field should match the directory containing SKILL.md, because "
                "loaders resolve skills by directory."
            ),
            impact=(
                "The skill is discovered under a name nothing references, so documentation, "
                "marketplace entries, and cross-skill references all point at nothing."
            ),
            remediation="Rename the directory or the 'name' field so the two agree.",
            references=(SPEC_URL,),
        ),
        RuleMeta(
            id="SPEC005",
            title="Field exceeds its length limit",
            family=Family.SPEC,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            explanation=(
                f"'name' is limited to {MAX_NAME} characters, 'description' to "
                f"{MAX_DESCRIPTION}, and 'compatibility' to {MAX_COMPATIBILITY}."
            ),
            impact="Over-long fields are truncated or rejected, changing or disabling the trigger.",
            remediation="Move detail into the body; frontmatter is for routing, not documentation.",
            references=(SPEC_URL,),
        ),
        RuleMeta(
            id="SPEC006",
            title="Unknown frontmatter key",
            family=Family.SPEC,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            explanation=(
                "Only name, description, license, allowed-tools, metadata and compatibility "
                "are defined at the top level. 'metadata' is the extension point for anything else."
            ),
            impact=(
                "Unknown keys are ignored by conforming loaders, so any behaviour the author "
                "expected from them silently does not happen."
            ),
            remediation="Move the key under 'metadata:'.",
            references=(SPEC_URL,),
        ),
        RuleMeta(
            id="SPEC007",
            title="Empty or missing body",
            family=Family.SPEC,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            explanation="A skill whose SKILL.md has no body after the frontmatter carries no instructions.",
            impact="The skill adds its description to the agent's context and nothing else.",
            remediation="Write the procedure the skill is supposed to encode.",
            references=(SPEC_URL,),
        ),
        RuleMeta(
            id="SPEC008",
            title="Field has the wrong type",
            family=Family.SPEC,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            explanation=(
                "'name', 'description' and 'license' must be strings; 'allowed-tools' a list "
                "of strings (a comma-separated string is tolerated by most loaders but is not "
                "the specified form); 'metadata' and 'compatibility' mappings."
            ),
            impact="A mistyped field is ignored or crashes the loader, disabling the skill.",
            remediation="Correct the value's type to match the specification.",
            references=(SPEC_URL,),
        ),
        RuleMeta(
            id="SPEC009",
            title="Description does not state when to use the skill",
            family=Family.SPEC,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The description is the only text the agent sees when deciding whether to load "
                "a skill. It needs to say what the skill does *and* the conditions under which "
                "it applies. This rule looks for trigger phrasing such as 'use when'."
            ),
            impact=(
                "Without a trigger condition the agent cannot route to the skill reliably; it "
                "loads at the wrong times or not at all."
            ),
            remediation=(
                "Use the shape: [what it does] + [when to use it] + [keywords the user would say]."
            ),
            limitations=(
                "This is a lexical proxy. A description can state a trigger in phrasing this "
                "rule does not recognise, and can contain the phrase 'use when' while saying "
                "nothing useful."
            ),
            references=(SPEC_URL, "https://arxiv.org/abs/2607.01456"),
            # Carried from the authoring-smell taxonomy as CSD
            # ("Confusing Skill Description"). It lives in SPEC rather than QUA
            # because a description with no trigger condition is a routing
            # failure, not a style preference: the skill does not load.
            taxonomy=("CSD",),
        ),
        RuleMeta(
            id="SPEC010",
            title="Referenced file does not exist",
            family=Family.SPEC,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            explanation=(
                "The body points the agent at a bundled file (for example "
                "'references/stride.md') that is not present in the skill directory."
            ),
            impact=(
                "The agent is told to load context that does not exist. In practice it either "
                "stops, or proceeds without the material and fabricates the missing content."
            ),
            remediation="Add the file, or remove the reference.",
            limitations="Only resolves relative paths that appear in Markdown links or backticks.",
            references=(SPEC_URL,),
        ),
    ]
)


@registry.implement(
    "SPEC001", "SPEC002", "SPEC003", "SPEC004", "SPEC005",
    "SPEC006", "SPEC007", "SPEC008", "SPEC009", "SPEC010",
)
def check_spec(context: AnalysisContext) -> Iterator[Finding]:
    skill = context.skill
    frontmatter = skill.frontmatter
    name = context.name
    entry = context.entry_path

    # -- structure ----------------------------------------------------------
    fatal_kinds = {
        IssueKind.NO_FRONTMATTER,
        IssueKind.UNCLOSED,
        IssueKind.NOT_AT_START,
        IssueKind.INVALID_YAML,
        IssueKind.NOT_A_MAPPING,
        IssueKind.ALIASES_REFUSED,
        IssueKind.TOO_LARGE,
    }
    structural = [i for i in frontmatter.issues if i.kind in fatal_kinds]
    for issue in structural:
        yield emit(
            "SPEC001",
            name,
            message=issue.message,
            evidence=[Evidence(path=entry, line=issue.line)],
        )

    for issue in frontmatter.issues:
        if issue.kind in (IssueKind.DUPLICATE_KEY, IssueKind.TAB_INDENT, IssueKind.UNPARSEABLE_LINE):
            yield emit(
                "SPEC001",
                name,
                message=issue.message,
                evidence=[Evidence(path=entry, line=issue.line)],
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
            )

    if structural or not frontmatter.present:
        return  # nothing below can be evaluated meaningfully

    data = frontmatter.data

    # -- required fields and types -----------------------------------------
    for field_name in ("name", "description"):
        if field_name not in data or data[field_name] in (None, ""):
            yield emit(
                "SPEC002",
                name,
                message=f"frontmatter is missing the required {field_name!r} field",
                evidence=[Evidence(path=entry, line=1)],
            )

    for field_name in ("name", "description", "license"):
        value = data.get(field_name)
        if value is not None and not isinstance(value, str):
            yield emit(
                "SPEC008",
                name,
                message=f"{field_name!r} must be a string, found {type(value).__name__}",
                evidence=[context.frontmatter_evidence(field_name)],
            )

    tools = data.get("allowed-tools")
    if tools is not None and not isinstance(tools, list):
        yield emit(
            "SPEC008",
            name,
            message=(
                f"'allowed-tools' should be a list of strings, found {type(tools).__name__}"
                + ("; the comma-separated string form is tolerated by most loaders but is not specified" if isinstance(tools, str) else "")
            ),
            evidence=[context.frontmatter_evidence("allowed-tools")],
            severity=Severity.LOW if isinstance(tools, str) else Severity.MEDIUM,
        )

    for field_name in ("metadata", "compatibility"):
        value = data.get(field_name)
        if value is not None and not isinstance(value, dict):
            yield emit(
                "SPEC008",
                name,
                message=f"{field_name!r} must be a mapping, found {type(value).__name__}",
                evidence=[context.frontmatter_evidence(field_name)],
            )

    # -- name ---------------------------------------------------------------
    declared_name = skill.name
    if declared_name:
        if len(declared_name) > MAX_NAME:
            yield emit(
                "SPEC005",
                name,
                message=f"name is {len(declared_name)} characters (limit {MAX_NAME})",
                evidence=[context.frontmatter_evidence("name")],
            )
        if not NAME_PATTERN.match(declared_name):
            yield emit(
                "SPEC003",
                name,
                message=f"name {declared_name!r} is not a valid identifier",
                evidence=[context.frontmatter_evidence("name", declared_name[:80])],
            )
        elif declared_name != skill.dir_name:
            yield emit(
                "SPEC004",
                name,
                message=f"name {declared_name!r} does not match directory {skill.dir_name!r}",
                evidence=[context.frontmatter_evidence("name", declared_name[:80])],
            )

    # -- description --------------------------------------------------------
    description = skill.description
    if description:
        if len(description) > MAX_DESCRIPTION:
            yield emit(
                "SPEC005",
                name,
                message=f"description is {len(description)} characters (limit {MAX_DESCRIPTION})",
                evidence=[context.frontmatter_evidence("description")],
            )
        if not _has_trigger(description):
            yield emit(
                "SPEC009",
                name,
                message="description does not state when the skill should be used",
                evidence=[context.frontmatter_evidence("description", description[:120])],
            )

    compatibility = data.get("compatibility")
    if isinstance(compatibility, str) and len(compatibility) > MAX_COMPATIBILITY:
        yield emit(
            "SPEC005",
            name,
            message=f"compatibility is {len(compatibility)} characters (limit {MAX_COMPATIBILITY})",
            evidence=[context.frontmatter_evidence("compatibility")],
        )

    # -- unknown keys -------------------------------------------------------
    for key in data:
        if key not in ALLOWED_KEYS:
            yield emit(
                "SPEC006",
                name,
                message=f"unknown frontmatter key {key!r}",
                evidence=[context.frontmatter_evidence(key)],
            )

    # -- body ---------------------------------------------------------------
    if not skill.body.strip():
        yield emit(
            "SPEC007",
            name,
            message="SKILL.md has no body after the frontmatter",
            evidence=[Evidence(path=entry, line=frontmatter.body_start_line)],
        )

    yield from _check_references(context)


TRIGGER_SIGNALS = (
    "use when", "use this when", "used when", "when the user", "when a user",
    "trigger", "invoke when", "apply when", "for when", "whenever",
    "call this when", "reach for this when", "use if", "use for", "applies when",
    "activate when", "run when", "when asked", "when you need",
)


def _has_trigger(description: str) -> bool:
    lowered = description.lower()
    return any(signal in lowered for signal in TRIGGER_SIGNALS)


#: Relative paths mentioned in the body, either as a Markdown link target or
#: inside backticks. Absolute paths and URLs are excluded.
_REFERENCE_RE = re.compile(
    r"\[[^\]]*\]\((?!https?://|#|mailto:)([^)\s]+)\)"
    r"|`((?:\./)?(?:references|scripts|assets|templates|examples|docs)/[\w./-]+)`"
)


def _check_references(context: AnalysisContext) -> Iterator[Finding]:
    skill = context.skill
    present = {f.scanned.relpath for f in context.files if not f.scanned.container}
    offset = skill.frontmatter.body_start_line - 1
    seen: set[str] = set()

    for match in _REFERENCE_RE.finditer(skill.body):
        target = (match.group(1) or match.group(2) or "").split("#", 1)[0].strip()
        if not target or target in seen:
            continue
        seen.add(target)
        normalised = target.removeprefix("./").rstrip("/")
        if not normalised or normalised.startswith(("/", "..")):
            continue
        # A directory reference is satisfied by any file beneath it.
        if normalised in present or any(p.startswith(f"{normalised}/") for p in present):
            continue
        if (skill.root / normalised).exists():
            continue
        line = skill.body.count("\n", 0, match.start()) + 1 + offset
        yield emit(
            "SPEC010",
            context.name,
            message=f"body references {normalised!r}, which is not present in the skill",
            evidence=[Evidence(path=context.entry_path, line=line, excerpt=match.group(0)[:120])],
        )
