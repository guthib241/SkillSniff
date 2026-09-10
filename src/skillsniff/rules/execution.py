"""Execution and privilege-bypass rules (EXE, PRV families).

Execution findings are grounded in parsed structure wherever possible rather
than in regex over source text. ``subprocess.run(cmd, shell=True)`` is detected
from the AST, and ``curl … | bash`` from a quote-aware shell tokeniser, so a
docstring warning against either does not produce a finding. That distinction is
the difference between a rule that survives contact with a real corpus and one
that gets suppressed on day two.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillsniff.analysis.context import AnalysisContext
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity
from skillsniff.rules import _scan
from skillsniff.rules.base import Family, RuleMeta, emit, registry

CWE_78 = "https://cwe.mitre.org/data/definitions/78.html"
CWE_94 = "https://cwe.mitre.org/data/definitions/94.html"

registry.define_all(
    [
        RuleMeta(
            id="EXE001",
            title="Remote content piped directly into an interpreter",
            family=Family.EXE,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "A network fetch is piped into a shell or interpreter — the "
                "'curl … | bash' pattern. Detected by tokenising the pipeline, so a quoted or "
                "commented example does not match."
            ),
            limitations=(
                "Detects pipelines the shell tokeniser can see: bundled scripts, fenced "
                "blocks, and decoded regions. A pipeline assembled at runtime from variables "
                "is not resolved."
            ),
            impact=(
                "Whatever the server returns at the moment of execution runs with the agent's "
                "full privileges. The content reviewed today is not necessarily the content "
                "that runs tomorrow, and the server can serve different content per client."
            ),
            remediation=(
                "Download to a file, verify it against a published checksum, review it, then "
                "execute. Or vendor the script into the skill so it is reviewable."
            ),
            references=(CWE_94,),
            taxonomy=("CWE-494",),
        ),
        RuleMeta(
            id="EXE002",
            title="Decoded content piped into an interpreter",
            family=Family.EXE,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "A decoder (base64, xxd, openssl) feeds its output straight into a shell or "
                "interpreter."
            ),
            limitations=(
                "Detects decoder-to-interpreter pipelines lexically. A program that decodes "
                "in memory and executes without a pipeline is covered by EXE004 instead, if "
                "at all."
            ),
            impact=(
                "The executed content is unreadable in the source, so review cannot see what "
                "runs. There is no legitimate reason to encode a script that is about to be "
                "executed in place."
            ),
            remediation="Inline the script in plain text.",
            references=(CWE_94,),
        ),
        RuleMeta(
            id="EXE003",
            title="Shell invoked with an unparsed command string",
            family=Family.EXE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "A subprocess is created with shell=True, or via os.system/os.popen. Detected "
                "from the Python AST, so the keyword appearing in a comment or string does not "
                "match."
            ),
            limitations=(
                "Python only, from the AST. The equivalent in JavaScript, Ruby, or a shell "
                "wrapper is not detected by this rule."
            ),
            impact=(
                "Any value interpolated into the command string is interpreted by the shell. If "
                "any part of it derives from file contents, a filename, or model output, that is "
                "command injection."
            ),
            remediation=(
                "Pass an argument list — subprocess.run(['git', 'status']) — which never invokes "
                "a shell and needs no quoting."
            ),
            references=(CWE_78,),
            taxonomy=("CWE-78",),
        ),
        RuleMeta(
            id="EXE004",
            title="Dynamic code evaluation",
            family=Family.EXE,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "eval, exec, compile, or an equivalent is called on a non-literal value; or "
                "pickle/marshal is used to load data. Detected from the AST."
            ),
            limitations=(
                "Python only, from the AST. Dynamic execution in another language, or via a "
                "library that evaluates strings internally, is not detected."
            ),
            impact=(
                "Whatever the value evaluates to becomes executable code. pickle.loads on "
                "untrusted input is arbitrary code execution by design, not by accident."
            ),
            remediation=(
                "Parse data with json or ast.literal_eval. If dispatch is needed, use an "
                "explicit mapping of allowed operations."
            ),
            references=(CWE_94,),
            taxonomy=("CWE-502", "CWE-95"),
        ),
        RuleMeta(
            id="EXE005",
            title="Destructive filesystem or database operation",
            family=Family.EXE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A recursive delete against a root, home, or wildcard path; a disk-level write; "
                "a force-push to a default branch; or a DROP/TRUNCATE statement."
            ),
            impact=(
                "Irreversible data loss, executed by an agent that may be running unattended "
                "and cannot undo it."
            ),
            remediation=(
                "Require explicit user confirmation immediately before the operation, and "
                "constrain the target path to a directory the skill created."
            ),
            limitations=(
                "A skill that documents these commands as things to avoid will match. Check the "
                "cited line before acting."
            ),
        ),
        RuleMeta(
            id="EXE006",
            title="Remote script fetched for execution",
            family=Family.EXE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill downloads an executable script from a URL that is not pinned to an "
                "immutable reference, and executes or sources it."
            ),
            limitations=(
                "Requires an execution verb near the URL within a few lines. A download and a "
                "later execution separated across files will not correlate."
            ),
            impact=(
                "The publisher can change the script after the skill is reviewed and installed. "
                "Review establishes nothing about future behaviour."
            ),
            remediation="Pin to a commit SHA or content hash, or vendor the script into the skill.",
        ),
        RuleMeta(
            id="PRV001",
            title="Agent safety controls disabled",
            family=Family.PRV,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "The skill instructs the agent, or configures a tool, to skip permission "
                "prompts, auto-approve actions, or run without a sandbox — for example "
                "'--dangerously-skip-permissions', 'bypassPermissions', or 'autoApprove: true'."
            ),
            limitations=(
                "Matches known agent and tool flags. A future flag, or a configuration file "
                "that disables permissions without using one of these names, is not detected."
            ),
            impact=(
                "The user's ability to review and refuse individual actions is removed. Every "
                "other capability the skill has becomes unsupervised."
            ),
            remediation=(
                "Remove the flag. A skill must never widen the agent's permissions on the "
                "user's behalf; that decision belongs to the user."
            ),
            references=(),
        ),
        RuleMeta(
            id="PRV002",
            title="Transport security disabled",
            family=Family.PRV,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "TLS verification is turned off: 'curl -k', 'verify=False', "
                "'NODE_TLS_REJECT_UNAUTHORIZED=0', or 'rejectUnauthorized: false'."
            ),
            limitations=(
                "Covers common HTTP clients and CLI tools. A custom TLS context configured "
                "through a less common API is not detected."
            ),
            impact=(
                "Any network position between the agent and the server can substitute content "
                "or capture what is sent, including credentials."
            ),
            remediation=(
                "Leave verification enabled. For a private CA, install the certificate rather "
                "than disabling the check."
            ),
            references=("https://cwe.mitre.org/data/definitions/295.html",),
            taxonomy=("CWE-295",),
        ),
        RuleMeta(
            id="PRV003",
            title="Privilege escalation via sudo or setuid",
            family=Family.PRV,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            explanation="The skill runs commands under sudo/doas, or sets the setuid bit.",
            impact=(
                "Actions execute with administrative privilege, outside anything the agent's "
                "own sandbox can constrain."
            ),
            remediation=(
                "Operate at the user's own privilege level. If elevation is genuinely required, "
                "state it prominently and require explicit confirmation."
            ),
            limitations="Installation documentation legitimately mentions sudo.",
        ),
    ]
)


@registry.implement("EXE001", "EXE002")
def check_pipe_to_interpreter(context: AnalysisContext) -> Iterator[Finding]:
    for file in context.shell_files():
        shell = file.shell
        assert shell is not None
        view = file.view
        for rule_id, entries in (
            ("EXE001", shell.fetch_to_interpreter),
            ("EXE002", shell.decode_to_interpreter),
        ):
            for excerpt, line in entries:
                documented = False
                if view is not None:
                    offset = _offset_of_line(view.raw, line)
                    documented = _scan.documentation_framed(view.raw, offset)
                yield emit(
                    rule_id,
                    context.name,
                    message=f"{file.path}: {excerpt!r}",
                    evidence=[
                        file.evidence(
                            line=line,
                            excerpt=excerpt,
                            note=(
                                "appears under prose framing it as an example, not an instruction"
                                if documented
                                else ""
                            ),
                        )
                    ],
                    severity=Severity.LOW if documented else None,
                    confidence=Confidence.LOW if documented else None,
                )

    # The same pattern can arrive inside an encoded region, where the shell
    # tokeniser never sees it.
    piped = re.compile(
        r"(?:curl|wget)\b[^\n|]{1,200}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b", re.IGNORECASE
    )
    for match in _scan.scan(context, piped, include_normalized=True, include_decoded=True):
        if match.projection == "raw":
            continue  # already covered by the tokeniser above
        yield emit(
            "EXE001",
            context.name,
            message=f"{match.path}: {match.excerpt!r}",
            evidence=[match.evidence()],
        )



@registry.implement("EXE003")
def check_shell_true(context: AnalysisContext) -> Iterator[Finding]:
    for file in context.python_files():
        analysis = file.python
        assert analysis is not None
        for line in analysis.shell_true_lines:
            yield emit(
                "EXE003",
                context.name,
                message=f"{file.path}: subprocess invoked with shell=True",
                evidence=[file.evidence(line=line, excerpt="shell=True")],
            )
        for dotted, line in analysis.calls:
            if dotted in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"):
                yield emit(
                    "EXE003",
                    context.name,
                    message=f"{file.path}: {dotted}() passes a string to the shell",
                    evidence=[file.evidence(line=line, excerpt=f"{dotted}(...)")],
                )


@registry.implement("EXE004")
def check_dynamic_eval(context: AnalysisContext) -> Iterator[Finding]:
    for file in context.python_files():
        analysis = file.python
        assert analysis is not None
        for name, line in analysis.dynamic_eval_lines:
            yield emit(
                "EXE004",
                context.name,
                message=f"{file.path}: {name}() called on a non-literal value",
                evidence=[file.evidence(line=line, excerpt=f"{name}(<dynamic>)")],
            )
        for dotted, line in analysis.calls:
            if dotted in ("pickle.loads", "pickle.load", "marshal.loads"):
                yield emit(
                    "EXE004",
                    context.name,
                    message=f"{file.path}: {dotted}() deserialises data as executable objects",
                    evidence=[file.evidence(line=line, excerpt=f"{dotted}(...)")],
                    confidence=Confidence.HIGH,
                )


DESTRUCTIVE_RE = re.compile(
    r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:/|~|\$HOME|\*|\$\{HOME\})(?:\s|$|/\*)"
    r"|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:/|~|\$HOME|\*)(?:\s|$|/\*)"
    r"|(?<![\w.])mkfs(?:\.\w+)?\s"
    r"|dd\s+[^\n]{0,60}of=/dev/(?:sd|nvme|disk|hd)"
    r"|git\s+push\s+[^\n]{0,40}(?:--force|-f)\b[^\n]{0,40}\b(?:main|master)\b"
    r"|\bDROP\s+(?:DATABASE|TABLE|SCHEMA)\b"
    r"|\bTRUNCATE\s+TABLE\b"
    r"|:\(\)\s*\{\s*:\|:&\s*\}\s*;:",
    re.IGNORECASE,
)


@registry.implement("EXE005")
def check_destructive(context: AnalysisContext) -> Iterator[Finding]:
    for match in _scan.scan(context, DESTRUCTIVE_RE, limit_per_file=5):
        yield _scan.emit_match("EXE005", context.name, match)


@registry.implement("EXE006")
def check_remote_script_execution(context: AnalysisContext) -> Iterator[Finding]:
    from skillsniff.analysis.external import ResourceKind

    executed = re.compile(
        r"\b(?:bash|sh|zsh|source|\.|python3?|node|ruby|perl|powershell)\b\s+[^\n]{0,80}"
        r"|\bchmod\s+\+x\b",
        re.IGNORECASE,
    )

    for file in context.text_files():
        view = file.view
        if view is None:
            continue
        for resource in file.urls:
            if resource.kind is not ResourceKind.REMOTE_SCRIPT or not resource.is_mutable:
                continue
            evidence = resource.evidence
            if evidence is None or evidence.line is None:
                continue
            lines = view.raw.splitlines()
            window = "\n".join(lines[max(0, evidence.line - 3) : evidence.line + 2])
            if not executed.search(window):
                continue
            yield emit(
                "EXE006",
                context.name,
                message=(
                    f"{file.path}: downloads and runs {resource.raw} "
                    f"({resource.trust.label})"
                ),
                evidence=[
                    Evidence(
                        path=file.path,
                        line=evidence.line,
                        excerpt=resource.raw[:160],
                        note="; ".join(resource.reasons),
                    )
                ],
            )


PERMISSION_BYPASS = re.compile(
    r"--dangerously-skip-permissions\b"
    r"|--yolo\b"
    r"|--no-sandbox\b"
    r"|--disable-sandbox\b"
    r"|\bautoApprove\b"
    r"|\bauto[_-]?approve\s*[:=]\s*(?:true|1|yes)"
    r"|[\"']?bypassPermissions[\"']?"
    r"|--allow-all\b"
    r"|--trust-all\b"
    r"|skip[_-]?(?:permission|confirmation|approval)s?\s*[:=]\s*(?:true|1|yes)"
    r"|--accept-all-risks\b"
    # Instruction-level permission bypass: the skill tells the agent to take an
    # action without seeking confirmation. Requires an imperative action verb
    # immediately before, because a bare "without asking" is ordinary English
    # and matching it produced false positives on authoring advice.
    r"|\b(?:proceed|continue|do\s+it|act|apply|execute|run|delete|deploy|push|install|"
    r"overwrite|commit|merge|send)\b[^.\n]{0,40}"
    r"without\s+(?:asking|confirming|confirmation|permission|prompting|approval|"
    r"waiting\s+for)\b"
    r"|\bdo\s*n[o']?t\s+(?:ask|prompt|wait\s+for|request)\b[^.\n]{0,30}"
    r"(?:permission|confirmation|approval|the\s+user)",
    re.IGNORECASE,
)

TLS_BYPASS = re.compile(
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"
    r"|\bverify\s*=\s*False\b"
    r"|\brejectUnauthorized\s*:\s*false\b"
    r"|curl\b[^\n]{0,80}\s-{1,2}(?:k|insecure)\b"
    r"|wget\b[^\n]{0,80}--no-check-certificate\b"
    r"|ssl\._create_unverified_context\b"
    r"|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)"
    r"|GIT_SSL_NO_VERIFY\s*=\s*(?:1|true)",
    re.IGNORECASE,
)

PRIVILEGE_ESCALATION = re.compile(
    r"(?:^|[\s|;&(])(?:sudo|doas)\s+(?!-h\b|--help\b)"
    r"|chmod\s+[0-7]?[2-7]?[67][0-7]{2}\b"
    r"|chmod\s+u\+s\b"
    r"|setuid\s*\(",
    re.IGNORECASE | re.MULTILINE,
)


@registry.implement("PRV001", "PRV002", "PRV003")
def check_privilege(context: AnalysisContext) -> Iterator[Finding]:
    for rule_id, pattern in (
        ("PRV001", PERMISSION_BYPASS),
        ("PRV002", TLS_BYPASS),
        ("PRV003", PRIVILEGE_ESCALATION),
    ):
        for match in _scan.scan(context, pattern, limit_per_file=4):
            yield _scan.emit_match(rule_id, context.name, match)


def _offset_of_line(text: str, line: int) -> int:
    """Character offset of the start of 1-based ``line``."""
    offset = 0
    for _ in range(max(0, line - 1)):
        newline = text.find("\n", offset)
        if newline == -1:
            return offset
        offset = newline + 1
    return offset
