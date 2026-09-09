"""Shell command analysis.

Shell text appears in three places in a skill: bundled ``.sh`` files, fenced
code blocks in SKILL.md, and string arguments to ``subprocess``. All three are
run through the same tokeniser so a pattern is not detected in one place and
missed in another.

``shlex`` handles quoting properly, which matters: ``echo "curl x | bash"`` is a
string, not a pipeline, and a scanner that cannot tell the difference produces
false positives on documentation that *warns* about an attack.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from skillsniff.model.capability import Capability, Observation, Source
from skillsniff.model.finding import Confidence, Evidence

NETWORK_FETCHERS = frozenset({"curl", "wget", "aria2c", "httpie", "http", "nc", "ncat", "netcat", "socat"})
SHELL_INTERPRETERS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "csh"})
INTERPRETERS = SHELL_INTERPRETERS | {"python", "python3", "perl", "ruby", "node", "php", "osascript"}
PACKAGE_INSTALLERS = {
    ("pip", "install"), ("pip3", "install"), ("npm", "install"), ("npm", "i"),
    ("yarn", "add"), ("pnpm", "add"), ("gem", "install"), ("cargo", "install"),
    ("go", "install"), ("apt", "install"), ("apt-get", "install"), ("brew", "install"),
    ("uv", "pip"), ("pipx", "install"),
}
DESTRUCTIVE = frozenset({"rm", "shred", "mkfs", "dd", "fdisk", "diskutil"})
CREDENTIAL_READERS = frozenset({"cat", "less", "more", "head", "tail", "strings", "base64", "cp", "tar", "zip"})
ENV_DUMPERS = frozenset({"env", "printenv", "set", "export"})

CREDENTIAL_PATHS = re.compile(
    r"(?:~|\$HOME|\$\{HOME\}|/home/[\w.-]+|/Users/[\w.-]+)?/?"
    r"\.(?:ssh|aws|gnupg|kube|docker|netrc|npmrc|pypirc|config/gh)\b"
    r"|(?:^|[\s/'\"])id_(?:rsa|ed25519|ecdsa|dsa)\b"
    r"|\.aws/credentials|\.config/gcloud|/etc/shadow|/etc/passwd"
    r"|credentials\.json|service[_-]account\.json",
    re.IGNORECASE,
)

SECRET_ENV = re.compile(
    r"\$\{?[A-Za-z_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY)[A-Za-z0-9_]*\}?",
    re.IGNORECASE,
)


@dataclass
class ShellCommand:
    """One parsed command within a pipeline."""

    argv: list[str]
    raw: str
    line: int

    @property
    def program(self) -> str:
        if not self.argv:
            return ""
        name = self.argv[0].rsplit("/", 1)[-1]
        return name.removesuffix(".exe")

    @property
    def args(self) -> list[str]:
        return self.argv[1:]


@dataclass
class ShellAnalysis:
    path: str
    commands: list[ShellCommand] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    #: Pipelines where a network fetch feeds an interpreter — `curl … | bash`.
    fetch_to_interpreter: list[tuple[str, int]] = field(default_factory=list)
    #: Pipelines where a decoder feeds an interpreter — `base64 -d | sh`.
    decode_to_interpreter: list[tuple[str, int]] = field(default_factory=list)
    #: Commands that read credentials and commands that send data, with lines.
    credential_reads: list[tuple[str, int]] = field(default_factory=list)
    network_sends: list[tuple[str, int]] = field(default_factory=list)
    installers: list[tuple[str, int]] = field(default_factory=list)
    destructive: list[tuple[str, int]] = field(default_factory=list)


#: Operators that separate one command from the next. Splitting must respect
#: quoting: `echo "a | b"` is a single command, and treating the quoted pipe as
#: a real one manufactures a `curl … | bash` finding out of documentation that
#: merely quotes the attack.
_PIPELINE_OPERATORS = ("||", "&&", "|", ";", "&")


def split_pipeline(line: str) -> list[str]:
    """Split a shell line on unquoted control operators."""
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    length = len(line)

    while index < length:
        ch = line[index]

        if quote:
            current.append(ch)
            if ch == "\\" and quote == '"' and index + 1 < length:
                current.append(line[index + 1])
                index += 2
                continue
            if ch == quote:
                quote = None
            index += 1
            continue

        if ch in "\"'":
            quote = ch
            current.append(ch)
            index += 1
            continue

        if ch == "\\" and index + 1 < length:
            current.append(ch)
            current.append(line[index + 1])
            index += 2
            continue

        matched = next((op for op in _PIPELINE_OPERATORS if line.startswith(op, index)), None)
        if matched:
            segments.append("".join(current))
            current = []
            index += len(matched)
            continue

        current.append(ch)
        index += 1

    segments.append("".join(current))
    return [segment.strip() for segment in segments if segment.strip()]


def has_unquoted_pipe(line: str) -> bool:
    """True when the line contains a real pipe operator, not a quoted one."""
    return len(split_pipeline(line)) > 1 and _UNQUOTED_PIPE.search(_blank_quoted(line)) is not None


_UNQUOTED_PIPE = re.compile(r"\|(?!\|)")


def _blank_quoted(line: str) -> str:
    """Replace quoted spans with spaces so operator scanning ignores them."""
    out: list[str] = []
    quote: str | None = None
    for ch in line:
        if quote:
            out.append(" ")
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(" ")
            continue
        out.append(ch)
    return "".join(out)


def _strip_comments(text: str) -> str:
    """Remove shell comments, which are documentation rather than behaviour."""
    out: list[str] = []
    for line in text.splitlines():
        in_single = in_double = False
        cut = len(line)
        for index, ch in enumerate(line):
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                if index == 0 or line[index - 1] in " \t":
                    cut = index
                    break
        out.append(line[:cut])
    return "\n".join(out)


def parse_shell(text: str, path: str, *, start_line: int = 1, strip_comments: bool = True) -> ShellAnalysis:
    """Tokenise shell text and extract capability observations."""
    analysis = ShellAnalysis(path=path)
    source = _strip_comments(text) if strip_comments else text

    for offset, raw_line in enumerate(source.splitlines()):
        line_no = start_line + offset
        if not raw_line.strip():
            continue

        segments = split_pipeline(raw_line)
        parsed: list[ShellCommand] = []
        for segment in segments:
            try:
                argv = shlex.split(segment, comments=False, posix=True)
            except ValueError:
                # Unbalanced quotes: fall back to whitespace splitting rather
                # than dropping the line, which would be a silent blind spot.
                argv = segment.split()
            if argv:
                parsed.append(ShellCommand(argv=argv, raw=segment, line=line_no))

        analysis.commands.extend(parsed)
        _analyse_pipeline(analysis, parsed, raw_line, line_no)

    return analysis


def _analyse_pipeline(
    analysis: ShellAnalysis, commands: list[ShellCommand], raw_line: str, line_no: int
) -> None:
    programs = [c.program for c in commands]

    # curl … | bash  (and the wget/nc equivalents)
    for index, program in enumerate(programs):
        piped = has_unquoted_pipe(raw_line)
        if program in NETWORK_FETCHERS and piped:
            downstream = programs[index + 1 :]
            if any(p in INTERPRETERS for p in downstream):
                analysis.fetch_to_interpreter.append((raw_line.strip()[:160], line_no))
        if program in ("base64", "xxd", "openssl", "uudecode") and piped:
            downstream = programs[index + 1 :]
            if any(p in INTERPRETERS for p in downstream):
                analysis.decode_to_interpreter.append((raw_line.strip()[:160], line_no))

    for command in commands:
        program = command.program
        excerpt = command.raw[:160]
        args = command.args

        def observe(capability: Capability, detail: str, confidence: Confidence = Confidence.HIGH) -> None:
            analysis.observations.append(
                Observation(
                    capability=capability,
                    source=Source.CODE,
                    confidence=confidence,
                    evidence=Evidence(path=analysis.path, line=line_no, excerpt=excerpt),
                    detail=detail,
                )
            )

        if program in NETWORK_FETCHERS:
            # Direction matters: retrieving remote content is an untrusted-input
            # channel, sending is an egress channel, and the compound rules need
            # to tell them apart.
            uploading = any(
                a in ("-d", "--data", "-F", "--form", "-T", "--upload-file", "--data-binary")
                for a in args
            ) or any(
                args[i] == "-X" and i + 1 < len(args) and args[i + 1].upper() in ("POST", "PUT", "PATCH")
                for i in range(len(args))
            ) or program in ("nc", "ncat", "netcat", "socat")
            if uploading:
                observe(Capability.NET_OUTBOUND, f"{program} sends data")
                analysis.network_sends.append((excerpt, line_no))
            else:
                observe(Capability.NET_FETCH, f"{program} retrieves remote content")

        if program in SHELL_INTERPRETERS:
            observe(Capability.SHELL_EXEC, f"invokes {program}")
        elif program in INTERPRETERS:
            observe(Capability.PROC_EXEC, f"invokes {program}")

        if program and (program, args[0] if args else "") in PACKAGE_INSTALLERS:
            analysis.installers.append((excerpt, line_no))
            observe(Capability.PKG_INSTALL, f"{program} {args[0]}")

        if program in DESTRUCTIVE:
            analysis.destructive.append((excerpt, line_no))
            observe(Capability.FS_DELETE, f"invokes {program}")

        if program in ENV_DUMPERS and program != "export":
            observe(Capability.ENV_READ, f"invokes {program}")

        if SECRET_ENV.search(command.raw):
            observe(Capability.CREDENTIAL_HANDLING, "references a secret-shaped variable")

        if CREDENTIAL_PATHS.search(command.raw):
            analysis.credential_reads.append((excerpt, line_no))
            observe(Capability.SECRET_ACCESS, "references a credential path")

        if program in ("git",) and args and args[0] in ("push", "commit", "config", "remote"):
            observe(Capability.GIT_WRITE, f"git {args[0]}", Confidence.MEDIUM)

        if program in ("chmod", "chown", "install", "ln", "mv", "cp", "tee", "touch", "mkdir"):
            observe(Capability.FS_WRITE, f"invokes {program}", Confidence.MEDIUM)

        if program in CREDENTIAL_READERS and any(CREDENTIAL_PATHS.search(a) for a in args):
            observe(Capability.SECRET_ACCESS, f"{program} reads a credential path")

        if ">" in _blank_quoted(raw_line):
            observe(Capability.FS_WRITE, "redirects output to a file", Confidence.MEDIUM)


FENCE_RE = re.compile(r"```+\s*([A-Za-z0-9_+-]*)\s*\n(.*?)```+", re.DOTALL)
SHELL_LANGS = frozenset({"sh", "bash", "shell", "zsh", "console", "terminal", "command", "sh-session", ""})


def shell_blocks(markdown: str) -> list[tuple[str, int, str]]:
    """Extract fenced shell blocks as (code, start_line, language)."""
    out: list[tuple[str, int, str]] = []
    for match in FENCE_RE.finditer(markdown):
        language = (match.group(1) or "").lower()
        if language not in SHELL_LANGS:
            continue
        start_line = markdown.count("\n", 0, match.start(2)) + 1
        out.append((match.group(2), start_line, language))
    return out
