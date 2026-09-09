"""Persistence, memory, and tool/MCP rules (PER, MEM, MCP families).

Persistence is where a one-time compromise becomes a standing one. A skill that
appends to a shell profile, an agent memory file, or a tool configuration is
changing what happens on every future session, long after the skill itself has
been forgotten.

The design tension here is that *legitimate* state management looks similar. A
skill that caches results in its own directory is not persisting an attack. So
these rules distinguish by target: writes into a skill-local path are not
reported, writes into shell profiles, agent instruction files, autostart
locations, and scheduler configuration are.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillsniff.analysis.context import AnalysisContext
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity
from skillsniff.rules import _scan
from skillsniff.rules.base import Family, RuleMeta, emit, registry

#: Files that change the behaviour of future shells or agent sessions.
SHELL_PROFILE = re.compile(
    r"(?:~|\$HOME|\$\{HOME\}|/home/[\w.-]+|/Users/[\w.-]+)?/?"
    r"\.(?:bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|profile|"
    r"cshrc|kshrc|config/fish/config\.fish|inputrc)\b",
    re.IGNORECASE,
)

AGENT_INSTRUCTION_FILE = re.compile(
    r"\b(?:CLAUDE|AGENTS?|GEMINI|CURSOR|COPILOT|WINDSURF|CONTINUE)\.md\b"
    r"|\.(?:claude|cursor|codex|continue|aider|windsurf)/(?:settings|config|rules|memory)"
    r"|\.cursorrules\b|\.aider\.conf\b|\.github/copilot-instructions\.md\b"
    r"|(?:^|/)memory\.(?:md|json|jsonl)\b",
    re.IGNORECASE,
)

AUTOSTART = re.compile(
    r"\bcrontab\b|/etc/cron|\bat\s+now\b"
    r"|LaunchAgents|LaunchDaemons|\.plist\b"
    r"|systemd/(?:user|system)|\.service\b|systemctl\s+(?:enable|start)"
    r"|/etc/rc\.local|/etc/init\.d"
    r"|(?:HKCU|HKLM)\\\\?Software\\\\?Microsoft\\\\?Windows\\\\?CurrentVersion\\\\?Run"
    r"|schtasks\s+/create|Register-ScheduledTask"
    r"|\.git/hooks/(?:pre|post|commit|prepare)"
    r"|core\.hooksPath",
    re.IGNORECASE,
)

WRITE_VERB = re.compile(
    r"\b(?:append|write|add|echo|cat|tee|printf|insert|inject|modify|edit|update|"
    r"patch|create|install|persist|save|register)\b"
    r"|>>|>\s*(?:~|\$HOME|/)",
    re.IGNORECASE,
)

MCP_CONFIG = re.compile(
    r"\bmcpServers?\b|\bmcp[_-]?config\b|\.mcp\.json\b|claude_desktop_config\.json"
    r"|\bmcp__[a-z0-9_]+__",
    re.IGNORECASE,
)

registry.define_all(
    [
        RuleMeta(
            id="PER001",
            title="Shell profile modification",
            family=Family.PER,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill writes to a shell startup file (.bashrc, .zshrc, .profile and "
                "similar). Requires both a profile path and a write verb nearby."
            ),
            impact=(
                "Anything added there executes on every future shell the user opens, "
                "indefinitely, with no further involvement from the skill or the agent. It "
                "survives uninstalling the skill."
            ),
            remediation=(
                "Do not modify shell startup files. If the user needs an environment change, "
                "print the line and let them add it themselves."
            ),
            limitations="Documentation showing a line to add will match. Check the cited line.",
            taxonomy=("MITRE-T1546",),
        ),
        RuleMeta(
            id="PER002",
            title="Scheduled task or autostart registration",
            family=Family.PER,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill registers a cron job, systemd unit, launch agent, Windows Run key, "
                "scheduled task, or Git hook."
            ),
            limitations=(
                "Matches known scheduler and autostart mechanisms across Linux, macOS and "
                "Windows. A platform-specific mechanism outside that set is not detected."
            ),
            impact=(
                "Code runs on a schedule or on an event, independent of the agent and outside "
                "any session the user is watching."
            ),
            remediation="Do not install background execution. Perform work in the foreground when invoked.",
            taxonomy=("MITRE-T1053",),
        ),
        RuleMeta(
            id="MEM001",
            title="Agent instruction file modification",
            family=Family.MEM,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill writes to a file that provides standing instructions to the agent — "
                "CLAUDE.md, AGENTS.md, .cursorrules, a memory file, or an agent settings file."
            ),
            impact=(
                "The skill is rewriting the agent's own instructions. Content placed there is "
                "loaded in every future session as trusted context, which converts a single "
                "execution into permanent influence over the agent."
            ),
            remediation=(
                "A skill should not write to the agent's instruction files. If the user wants "
                "persistent guidance, they should add it deliberately."
            ),
            limitations=(
                "A skill whose stated purpose is managing these files (a memory-management or "
                "project-scaffolding skill) will match legitimately."
            ),
            taxonomy=("LLM01:PromptInjection",),
        ),
        RuleMeta(
            id="MEM002",
            title="Instruction to persist information across sessions",
            family=Family.MEM,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            explanation=(
                "The instruction body tells the agent to remember something for future "
                "sessions."
            ),
            impact=(
                "Cross-session state that the user did not ask for changes the agent's "
                "behaviour later, at a point where the cause is no longer visible."
            ),
            remediation="State explicitly what is stored, where, and how the user removes it.",
            limitations=(
                "Many skills legitimately maintain state. This is informational and should not "
                "on its own be treated as a defect."
            ),
        ),
        RuleMeta(
            id="MCP001",
            title="MCP or tool configuration modification",
            family=Family.MCP,
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill writes to an MCP server configuration — .mcp.json, "
                "claude_desktop_config.json, or an mcpServers block."
            ),
            limitations=(
                "Requires a write verb near the configuration path. A skill that documents an "
                "MCP configuration without writing it matches at reduced confidence; one that "
                "writes it through an indirection does not match."
            ),
            impact=(
                "Adding an MCP server grants the agent a new set of tools from a new source, "
                "permanently and for every project. It is equivalent to installing software "
                "with the agent's full trust."
            ),
            remediation=(
                "Do not modify tool configuration. Document the server and let the user install it."
            ),
            taxonomy=("LLM01:PromptInjection",),
        ),
        RuleMeta(
            id="MCP002",
            title="Undeclared tool invocation",
            family=Family.MCP,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            explanation=(
                "The body instructs the agent to use a tool that is not listed in "
                "'allowed-tools'. Only reported when the skill declares allowed-tools at all, "
                "since an absent declaration means 'unrestricted' rather than 'none'."
            ),
            impact=(
                "The declared tool list is what a reviewer or policy engine uses to reason "
                "about the skill's reach. A skill using tools outside it has a wider surface "
                "than its declaration suggests."
            ),
            remediation="Add the tool to allowed-tools, or stop using it.",
            limitations=(
                "Tool names are matched lexically in prose, so a skill discussing a tool by "
                "name without using it can match."
            ),
        ),
        RuleMeta(
            id="MCP003",
            title="Overly broad tool declaration",
            family=Family.MCP,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            explanation=(
                "'allowed-tools' grants unrestricted shell access (a bare 'Bash' with no command "
                "scoping) or uses a bare wildcard."
            ),
            impact=(
                "Unscoped shell access is every capability at once: filesystem, network, "
                "process execution, credential access. No further restriction applies."
            ),
            remediation=(
                "Scope the grant to the commands actually needed, e.g. 'Bash(git status:*)'."
            ),
            limitations="Some agent platforms do not support scoped tool grants.",
        ),
    ]
)


def _write_near(view_text: str, line: int, window: int = 2) -> bool:
    """True if a write verb appears within ``window`` lines of ``line``."""
    lines = view_text.splitlines()
    start = max(0, line - 1 - window)
    return bool(WRITE_VERB.search("\n".join(lines[start : line + window])))


def _targeted(context: AnalysisContext, pattern: re.Pattern[str]) -> Iterator[tuple[str, int, str]]:
    """Yield (path, line, excerpt) where ``pattern`` matches near a write verb."""
    for match in _scan.scan(context, pattern, limit_per_file=6):
        view = match.file.view
        if view is None:
            continue
        if _write_near(view.raw, match.line):
            yield match.path, match.line, match.excerpt


@registry.implement("PER001")
def check_shell_profile(context: AnalysisContext) -> Iterator[Finding]:
    for path, line, excerpt in _targeted(context, SHELL_PROFILE):
        yield emit(
            "PER001",
            context.name,
            message=f"{path}: writes to a shell startup file — {excerpt!r}",
            evidence=[Evidence(path=path, line=line, excerpt=excerpt)],
        )


@registry.implement("PER002")
def check_autostart(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, AUTOSTART, limit_per_file=5):
        yield emit(
            "PER002",
            context.name,
            message=f"{match.path}: {match.excerpt!r}",
            evidence=[match.evidence()],
        )


@registry.implement("MEM001")
def check_agent_instruction_write(context: AnalysisContext) -> Iterator[Finding]:
    for path, line, excerpt in _targeted(context, AGENT_INSTRUCTION_FILE):
        yield emit(
            "MEM001",
            context.name,
            message=f"{path}: writes to an agent instruction file — {excerpt!r}",
            evidence=[Evidence(path=path, line=line, excerpt=excerpt)],
        )


PERSIST_INSTRUCTION = re.compile(
    r"\b(?:remember|persist|store|save|retain|record|keep)\b[^.\n]{0,50}"
    r"(?:across\s+sessions?|between\s+sessions?|for\s+(?:next|future|later)\s+time|"
    r"permanently|in\s+(?:your\s+)?memory|for\s+all\s+future)",
    re.IGNORECASE,
)


@registry.implement("MEM002")
def check_persist_instruction(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, PERSIST_INSTRUCTION, limit_per_file=3):
        yield emit(
            "MEM002",
            context.name,
            message=f"{match.path}: {match.excerpt!r}",
            evidence=[match.evidence()],
        )


@registry.implement("MCP001")
def check_mcp_config(context: AnalysisContext) -> Iterator[Finding]:
    for path, line, excerpt in _targeted(context, MCP_CONFIG):
        yield emit(
            "MCP001",
            context.name,
            message=f"{path}: modifies tool/MCP configuration — {excerpt!r}",
            evidence=[Evidence(path=path, line=line, excerpt=excerpt)],
        )


#: Tool names recognised when looking for undeclared use in prose.
_KNOWN_TOOLS = (
    "Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep",
    "WebFetch", "WebSearch", "Task", "NotebookEdit", "Computer",
)


@registry.implement("MCP002")
def check_undeclared_tools(context: AnalysisContext) -> Iterator[Finding]:
    declared = context.skill.declared_tools
    if not declared:
        return  # no declaration means unrestricted, not empty

    declared_heads = {re.split(r"[(\[:\s]", t.strip(), maxsplit=1)[0].lower() for t in declared}
    body = context.skill.body
    offset = context.skill.frontmatter.body_start_line - 1

    for tool in _KNOWN_TOOLS:
        if tool.lower() in declared_heads:
            continue
        # Require the tool to be named as a tool: backticked, or followed by
        # "tool". A skill that says "read the file" is not using the Read tool.
        pattern = re.compile(rf"`{tool}`|\b{tool}\s+tool\b|\buse\s+(?:the\s+)?{tool}\b")
        match = pattern.search(body)
        if not match:
            continue
        line = body.count("\n", 0, match.start()) + 1 + offset
        yield emit(
            "MCP002",
            context.name,
            message=f"body uses the {tool!r} tool, which is not in allowed-tools",
            evidence=[
                Evidence(path=context.entry_path, line=line, excerpt=match.group(0)[:80]),
                context.frontmatter_evidence("allowed-tools", ", ".join(declared)[:120]),
            ],
        )


@registry.implement("MCP003")
def check_broad_tools(context: AnalysisContext) -> Iterator[Finding]:
    for tool in context.skill.declared_tools:
        stripped = tool.strip()
        if stripped in ("*", "all", "Bash", "bash", "Shell", "shell"):
            yield emit(
                "MCP003",
                context.name,
                message=(
                    f"allowed-tools grants {stripped!r}"
                    + (" — unscoped shell access" if stripped.lower() in ("bash", "shell") else " — every tool")
                ),
                evidence=[context.frontmatter_evidence("allowed-tools", stripped)],
            )
