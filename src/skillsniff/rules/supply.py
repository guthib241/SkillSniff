"""Supply chain, network, and archive rules (SUP, NET, ARC families).

The organising idea is *mutability*. A skill that depends on something which can
change after review has not been meaningfully reviewed, and that is true whether
the changing thing is a package version, a Git branch, a URL, or an instruction
file fetched at runtime. These rules find the mutable edges of a skill's trust
boundary and name them.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillsniff.analysis.context import AnalysisContext
from skillsniff.analysis.external import ResourceKind, TrustLevel
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity
from skillsniff.rules import _scan
from skillsniff.rules.base import Family, RuleMeta, emit, registry

SLSA = "https://slsa.dev/"

registry.define_all(
    [
        RuleMeta(
            id="SUP001",
            title="Unpinned dependency",
            family=Family.SUP,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            explanation=(
                "A dependency is declared with a version range, a moving tag, or no constraint "
                "at all, so resolution picks whatever is newest at install time."
            ),
            impact=(
                "The code that runs is not the code that was reviewed. A compromise of the "
                "upstream package, or of the maintainer's account, reaches this skill "
                "automatically and without any change to this repository."
            ),
            remediation=(
                "Pin to an exact version, and to an artifact hash where the ecosystem supports "
                "it (pip --hash, npm lockfile integrity)."
            ),
            references=(SLSA,),
            taxonomy=("CWE-1357",),
        ),
        RuleMeta(
            id="SUP002",
            title="Install-time script hook",
            family=Family.SUP,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "package.json declares a preinstall, install, postinstall, or prepare script. "
                "These execute automatically when dependencies are installed."
            ),
            limitations=(
                "npm lifecycle hooks only. The equivalent in other ecosystems (setup.py build "
                "hooks, Cargo build scripts, Gradle tasks) is not yet parsed."
            ),
            impact=(
                "Code runs before anyone has chosen to run anything, and before any review of "
                "the installed tree. This is the primary npm supply-chain execution vector."
            ),
            remediation=(
                "Remove the hook and perform the work explicitly at a point the user controls."
            ),
            references=(SLSA,),
        ),
        RuleMeta(
            id="SUP003",
            title="Dependency fetched from a VCS branch",
            family=Family.SUP,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            explanation=(
                "A dependency points at a Git repository without a commit pin, so it tracks "
                "whatever the branch currently holds."
            ),
            impact="The dependency's contents can change at any time with no version bump to notice.",
            remediation="Pin the dependency to a full commit SHA.",
            references=(SLSA,),
        ),
        RuleMeta(
            id="SUP004",
            title="Package installed at runtime",
            family=Family.SUP,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill instructs the agent to install a package while it runs, rather than "
                "declaring it as a dependency."
            ),
            limitations=(
                "Matches installer command lines. A skill that installs a package through a "
                "library call rather than a command is not detected by this rule."
            ),
            impact=(
                "Runtime installation bypasses lockfiles, review, and any dependency scanning "
                "the project has. A typosquatted or newly-compromised package is pulled in "
                "silently."
            ),
            remediation=(
                "Declare dependencies in a manifest so they are visible, pinnable, and scannable."
            ),
            references=(SLSA,),
        ),
        RuleMeta(
            id="SUP005",
            title="Skill fetches its instructions from a remote source",
            family=Family.SUP,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill directs the agent to retrieve instructions, rules, prompts, or "
                "configuration from a URL at runtime and act on them."
            ),
            limitations=(
                "Matches English phrasing that describes fetching instructions. A skill that "
                "fetches remote content without describing it in these terms is reported by "
                "NET001 at much lower severity instead."
            ),
            impact=(
                "The skill's real behaviour lives at the far end of that URL and can be changed "
                "at any time by whoever controls it. Reviewing this skill tells you nothing "
                "about what it will instruct the agent to do."
            ),
            remediation=(
                "Vendor the instructions into the skill so they are versioned and reviewable. "
                "If remote content is essential, pin it by content hash and verify before use."
            ),
            references=(
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            ),
            taxonomy=("LLM01:PromptInjection",),
        ),
        RuleMeta(
            id="NET001",
            title="Mutable external reference",
            family=Family.NET,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            explanation=(
                "The skill references remote content that is not pinned — a branch URL, a bare "
                "domain, or a 'latest' link."
            ),
            impact="What the reference resolves to can change after the skill is reviewed.",
            remediation="Pin to a commit SHA or a versioned release URL.",
            limitations=(
                "Documentation links are matched too. This rule is informational by design; "
                "EXE006 and SUP005 carry the higher severity where the content is executed or "
                "obeyed."
            ),
        ),
        RuleMeta(
            id="NET002",
            title="Hardcoded IP address endpoint",
            family=Family.NET,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A network endpoint is written as a raw IP address. Private ranges and "
                "localhost are excluded as ordinary development references."
            ),
            impact=(
                "A literal IP has no certificate identity and no DNS reputation, and it survives "
                "domain takedown. It is common in payload infrastructure."
            ),
            remediation="Use a hostname over TLS, or remove the endpoint.",
        ),
        RuleMeta(
            id="NET003",
            title="Plaintext HTTP endpoint",
            family=Family.NET,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            explanation="A resource is fetched over http:// rather than https://.",
            impact="Content can be observed and modified in transit by any intermediary.",
            remediation="Use https:// so the content cannot be observed or altered in transit.",
            limitations="Localhost and private-range URLs are excluded.",
        ),
        RuleMeta(
            id="ARC001",
            title="Archive path traversal attempt",
            family=Family.ARC,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "An archive bundled with the skill contains a member whose name escapes the "
                "extraction directory via '..', an absolute path, or a drive letter. SkillSniff "
                "refuses such members and never extracts to disk."
            ),
            limitations=(
                "Detects traversal in ZIP and TAR members. An archive format this scanner "
                "does not parse, or one whose members are encrypted, is reported as a "
                "coverage gap by ARC002 instead."
            ),
            impact=(
                "Extracting the archive with an ordinary tool would write outside the intended "
                "directory — overwriting shell profiles, SSH keys, or agent configuration. This "
                "is Zip Slip."
            ),
            remediation=(
                "Rebuild the archive with relative paths inside a single top-level directory, or "
                "remove it."
            ),
            references=("https://cwe.mitre.org/data/definitions/22.html",),
            taxonomy=("CWE-22",),
        ),
        RuleMeta(
            id="ARC002",
            title="Archive could not be fully inspected",
            family=Family.ARC,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            explanation=(
                "An archive was encrypted, exceeded the decompression-ratio limit, nested deeper "
                "than the depth limit, or otherwise could not be read."
            ),
            impact=(
                "Content inside it was not analysed. Any 'no issues found' result excludes "
                "whatever this archive contains."
            ),
            remediation=(
                "Ship the contents unarchived so they can be reviewed, or remove the archive."
            ),
        ),
        RuleMeta(
            id="ARC003",
            title="Archive bundled with the skill",
            family=Family.ARC,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            explanation=(
                "The skill bundles an archive. SkillSniff inspects inside it, but archives make "
                "human review substantially less likely to happen."
            ),
            impact="Content that reviewers are unlikely to open, shipped inside the artifact.",
            remediation="Ship the files unarchived unless there is a specific reason not to.",
        ),
    ]
)


@registry.implement("SUP001", "SUP002", "SUP003")
def check_dependencies(context: AnalysisContext) -> Iterator[Finding]:
    for dependency in context.dependencies:
        if dependency.name.startswith("script:"):
            yield emit(
                "SUP002",
                context.name,
                message=(
                    f"{dependency.evidence.path}: {dependency.name.removeprefix('script:')} hook "
                    f"runs {dependency.version_spec!r}"
                ),
                evidence=[dependency.evidence],
            )
            continue

        if dependency.is_git and dependency.trust is not TrustLevel.PINNED:
            yield emit(
                "SUP003",
                context.name,
                message=f"{dependency.name} is a VCS dependency with no commit pin",
                evidence=[dependency.evidence],
            )
            continue

        if dependency.trust in (TrustLevel.MUTABLE, TrustLevel.UNKNOWN):
            yield emit(
                "SUP001",
                context.name,
                message=(
                    f"{dependency.name}{dependency.version_spec} — "
                    f"{'; '.join(dependency.reasons)}"
                ),
                evidence=[dependency.evidence],
            )


RUNTIME_INSTALL = re.compile(
    r"\b(?:pip3?|uv\s+pip|pipx)\s+install\b"
    r"|\bnpm\s+(?:install|i|exec)\b"
    r"|\bnpx\s+(?!--?\w*help)"
    r"|\byarn\s+add\b|\bpnpm\s+add\b"
    r"|\bgem\s+install\b|\bcargo\s+install\b|\bgo\s+install\b"
    r"|\b(?:apt|apt-get|yum|dnf|apk)\s+install\b|\bbrew\s+install\b",
    re.IGNORECASE,
)


@registry.implement("SUP004")
def check_runtime_install(context: AnalysisContext) -> Iterator[Finding]:
    seen: set[str] = set()
    for match in _scan.scan(context, RUNTIME_INSTALL, limit_per_file=6):
        key = f"{match.path}:{match.line}"
        if key in seen:
            continue
        seen.add(key)
        yield emit(
            "SUP004",
            context.name,
            message=f"{match.path}: {match.excerpt!r}",
            evidence=[match.evidence()],
        )


REMOTE_INSTRUCTIONS = re.compile(
    r"\b(?:fetch|download|curl|wget|retrieve|load|read|pull|get)\b[^.\n]{0,60}"
    r"\b(?:instruction|prompt|directive|rule|guideline|playbook|policy|config\w*|manifest|"
    r"system\s+message|context)s?\b[^.\n]{0,50}"
    r"\b(?:from|at|via)\b[^.\n]{0,40}(?:https?://|gist|pastebin|s3\.|bucket|endpoint|api)"
    r"|\b(?:follow|obey|execute|apply|comply\s+with)\b[^.\n]{0,40}"
    r"\b(?:the\s+)?(?:instruction|directive|command|rule)s?\b[^.\n]{0,40}"
    r"\b(?:returned|received|fetched|downloaded|found)\b[^.\n]{0,30}"
    r"\b(?:from|at|by)\b[^.\n]{0,30}(?:https?://|the\s+(?:server|endpoint|api|url|response))",
    re.IGNORECASE,
)


@registry.implement("SUP005")
def check_remote_instructions(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, REMOTE_INSTRUCTIONS, limit_per_file=4):
        yield emit(
            "SUP005",
            context.name,
            message=f"{match.path}: {match.excerpt!r}",
            evidence=[match.evidence()],
        )


@registry.implement("NET001", "NET002", "NET003")
def check_network_references(context: AnalysisContext) -> Iterator[Finding]:
    from skillsniff.analysis.external import is_benign_host

    seen: set[str] = set()
    for file in context.text_files():
        for resource in file.urls:
            if resource.raw in seen:
                continue
            seen.add(resource.raw)
            evidence = resource.evidence or Evidence(path=file.path)
            benign = is_benign_host(resource.host)

            if resource.host and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", resource.host) and not benign:
                yield emit(
                    "NET002",
                    context.name,
                    message=f"{file.path}: raw IP endpoint {resource.raw}",
                    evidence=[evidence],
                )

            if resource.scheme == "http" and not benign:
                yield emit(
                    "NET003",
                    context.name,
                    message=f"{file.path}: plaintext HTTP {resource.raw}",
                    evidence=[evidence],
                )

            if (
                resource.is_mutable
                and not benign
                and resource.kind in (ResourceKind.RAW_FILE, ResourceKind.REMOTE_SCRIPT, ResourceKind.GIT_REPO)
            ):
                yield emit(
                    "NET001",
                    context.name,
                    message=f"{file.path}: {resource.raw} — {'; '.join(resource.reasons)}",
                    evidence=[evidence],
                )


@registry.implement("ARC001", "ARC002", "ARC003")
def check_archives(context: AnalysisContext) -> Iterator[Finding]:
    from skillsniff.core.fs import FileKind
    from skillsniff.core.limits import CoverageReason

    for gap in context.budget.gaps:
        if gap.reason is CoverageReason.UNSAFE_PATH and "archive member" in gap.detail:
            yield emit(
                "ARC001",
                context.name,
                message=f"{gap.path}: {gap.detail}",
                evidence=[
                    Evidence(
                        path=gap.path,
                        excerpt=gap.detail,
                        note="member refused; SkillSniff never extracts archives to disk",
                    )
                ],
            )
        elif gap.reason in (
            CoverageReason.ENCRYPTED_ARCHIVE,
            CoverageReason.DECOMPRESSION_BOMB,
            CoverageReason.ARCHIVE_TOO_DEEP,
            CoverageReason.ARCHIVE_TOO_MANY_ENTRIES,
        ):
            yield emit(
                "ARC002",
                context.name,
                message=f"{gap.path}: {gap.reason.value} — {gap.detail}",
                evidence=[Evidence(path=gap.path, excerpt=gap.detail, note="content not analysed")],
            )

    for file in context.files:
        if file.scanned.kind == FileKind.ARCHIVE and not file.scanned.container:
            nested = sum(1 for f in context.files if f.scanned.container.startswith(file.path))
            yield emit(
                "ARC003",
                context.name,
                message=f"{file.path}: archive containing {nested} inspected entr{'y' if nested == 1 else 'ies'}",
                evidence=[
                    Evidence(
                        path=file.path,
                        excerpt=f"{file.scanned.size} bytes",
                        note=f"{nested} entries inspected",
                    )
                ],
            )
