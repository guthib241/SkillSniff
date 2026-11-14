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

import ast
import re
import shlex
from dataclasses import dataclass, field
from functools import cached_property

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

#: Commands that run another command given in their arguments, each with the
#: options that consume a value. ``sudo -E bash -`` runs ``bash -`` exactly as
#: the bare command would, so analysing the wrapper instead of what it runs
#: made ``curl … | sudo bash`` invisible.
WRAPPERS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-C", "-D", "-g", "-h", "-p", "-R", "-T", "-u", "-U", "-r", "-t", "--chdir",
                       "--close-from", "--group", "--host", "--prompt", "--role", "--type", "--user",
                       "--other-user", "--command-timeout"}),
    "doas": frozenset({"-C", "-u"}),
    "env": frozenset({"-u", "-C", "--unset", "--chdir"}),
    "nohup": frozenset(),
    "time": frozenset({"-f", "-o", "--format", "--output"}),
    "command": frozenset(),
    "exec": frozenset({"-a"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_VERSIONED = re.compile(r"(python|pypy|ruby|perl|php)(\d+(?:\.\d+)*)?")


def unwrap(argv: list[str]) -> list[str]:
    """The command that actually runs: ``sudo -E env X=1 nohup bash -`` runs ``bash -``.

    A wrapper with nothing after it stays itself — bare ``env`` prints the
    environment — except ``sudo -s`` and ``sudo -i``, which start a shell, and
    ``command -v``, which only looks a name up and runs nothing.
    """
    current = argv
    for _ in range(8):  # wrappers nest, but not without bound
        rest = current
        while rest and _ASSIGNMENT.match(rest[0]):
            rest = rest[1:]  # `FOO=1 bash`: an environment assignment, then the command
        if not rest:
            return current
        name = rest[0].rsplit("/", 1)[-1].removesuffix(".exe")
        takes_value = WRAPPERS.get(name)
        if takes_value is None:
            return rest
        inner = rest[1:]
        starts_shell = False
        while inner and inner[0].startswith("-") and inner[0] != "-":
            option = inner[0]
            if option == "--":
                inner = inner[1:]
                break
            if name == "command" and option in ("-v", "-V"):
                return []
            if name in ("sudo", "doas") and option in ("-s", "-i", "--shell", "--login"):
                starts_shell = True
            if name == "env" and option in ("-S", "--split-string") and len(inner) > 1:
                try:
                    inner = shlex.split(inner[1]) + inner[2:]
                except ValueError:
                    inner = inner[1].split() + inner[2:]
                continue
            consumes = option.split("=", 1)[0] in takes_value and "=" not in option
            inner = inner[2:] if consumes else inner[1:]
        if name == "timeout" and inner:
            inner = inner[1:]  # its first operand is the duration
        while name == "env" and inner and _ASSIGNMENT.match(inner[0]):
            inner = inner[1:]
        if not inner:
            return ["sh"] if starts_shell else rest
        current = inner
    return current


def interpreter_name(program: str) -> str:
    """``python3.12`` is ``python3``, ``ruby3.2`` is ``ruby``, ``nodejs`` is ``node``."""
    if program == "nodejs":
        return "node"
    match = _VERSIONED.fullmatch(program)
    if match is None or match.group(2) is None:
        return program
    family, version = match.group(1), match.group(2)
    if family in ("python", "pypy"):
        return "python3" if version.startswith("3") else "python"
    return family


#: Python modules whose command-line entry point parses its input and prints
#: it, running none of it: ``curl … | python3 -m json.tool`` pretty-prints JSON.
DATA_MODULES = frozenset({"json.tool", "json"})
#: Paths through which an interpreter reads its program from standard input.
_STDIN_PATHS = frozenset({"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"})
_PYTHON_VALUE_OPTIONS = frozenset({"-W", "-X", "--check-hash-based-pycs"})
#: What inline Python may use and still count as reading its input as data:
#: two modules, builtins that cannot reach code execution, and attribute names
#: that exist on files, strings, lists and dicts. Anything else — ``exec``,
#: ``__import__``, ``getattr``, ``os``, a dunder — keeps the pipe an execution.
_SAFE_IMPORTS = frozenset({"json", "sys"})
_SAFE_NAMES = frozenset({
    "print", "len", "str", "int", "float", "bool", "list", "dict", "tuple", "set", "sorted",
    "reversed", "enumerate", "zip", "range", "min", "max", "sum", "any", "all", "round", "abs",
    "isinstance", "repr", "map", "filter", "next", "iter", "chr", "ord", "hex", "format",
    "KeyError", "IndexError", "ValueError", "TypeError", "Exception", "StopIteration",
})
_SAFE_ATTRIBUTES = frozenset({
    "load", "loads", "dump", "dumps", "stdin", "stdout", "stderr", "argv", "exit", "read",
    "readline", "readlines", "write", "flush", "get", "keys", "values", "items", "join", "split",
    "rsplit", "splitlines", "strip", "lstrip", "rstrip", "lower", "upper", "title", "replace",
    "startswith", "endswith", "format", "append", "extend", "count", "index", "find", "rfind",
    "sort", "copy", "isdigit", "isalpha", "isalnum", "isspace", "encode", "decode", "partition",
    "rpartition", "zfill", "setdefault", "update", "pop",
})
_UNSAFE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Global, ast.Nonlocal,
                 ast.Await, ast.Yield, ast.YieldFrom, ast.AsyncFor, ast.AsyncWith, ast.With, ast.Delete)
#: Things in the same text that can make an interpreter's name, or its
#: interactive mode, mean something else: a function or alias named after
#: Python, ``PYTHONINSPECT`` (interactive after the program, reading stdin),
#: or a changed ``PATH``. Where any appears, no pipe into Python is exempt.
#: Horizontal whitespace only: ``^\s*`` under MULTILINE crosses newlines and
#: turns a file of blank lines into quadratic work (see test_performance.py).
_SHADOWING = re.compile(
    r"(?m)^[ \t]*(?:function[ \t]+)?(?:python[\d.]*|pypy[\d.]*)[ \t]*(?:\([ \t]*\)|\{)"
    r"|\bfunction[ \t]+(?:python[\d.]*|pypy[\d.]*)\b"
    r"|\balias[ \t]+(?:python[\d.]*|pypy[\d.]*)="
    r"|\bPYTHONINSPECT\b|\bPATH="
)


def shadows_interpreters(text: str) -> bool:
    """Whether ``text`` could make a pipe into ``python`` run something else."""
    return _SHADOWING.search(text) is not None


def _reads_as_data(code: str) -> bool:
    """Whether inline Python provably treats its input as data and executes none of it."""
    if len(code) > 2000:
        return False
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, _UNSAFE_NODES):
            return False
        if isinstance(node, ast.Import):
            if any(alias.name not in _SAFE_IMPORTS for alias in node.names):
                return False
            bound.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module not in _SAFE_IMPORTS or node.level:
                return False
            if any(alias.name == "*" for alias in node.names):
                return False
            bound.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in _SAFE_NAMES and node.id not in bound:
                return False
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("_") or node.attr not in _SAFE_ATTRIBUTES:
                return False
    return True


def _python_reads_data(args: list[str]) -> bool:
    """Whether ``python ARGS``, fed a pipe, treats it as data rather than a program."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--" or not arg.startswith("-") or arg in _STDIN_PATHS:
            return False  # the program is a script, or standard input itself
        if arg.startswith("--"):
            index += 2 if arg in _PYTHON_VALUE_OPTIONS else 1
            continue
        letters = arg[1:]
        for position, letter in enumerate(letters):
            if letter == "i":
                return False  # interactive after the program: it then runs its input
            if letter in "cm":
                value = letters[position + 1:]
                if not value:
                    value = args[index + 1] if index + 1 < len(args) else ""
                return value in DATA_MODULES if letter == "m" else _reads_as_data(value)
            if letter in "WX":
                index += 1 if letters[position + 1:] else 2
                break
        else:
            index += 1
    return False  # no program given: it reads one from standard input


def executes_stdin(command: ShellCommand, *, trust_names: bool = True) -> bool:
    """Whether ``command`` runs what is piped into it as a program.

    Every shell does, and so does any interpreter given no program of its own:
    ``| python3``, ``| python3 -``, ``| node /dev/stdin``. One given a program —
    a module, inline code, a script — receives the input as data, but whether
    that program then executes it can rarely be known statically, so only two
    Python cases are exempt: a module from ``DATA_MODULES``, and inline code
    that ``_reads_as_data`` accepts. A script path is still treated as running
    its input, because what the script does with it is not visible here.
    """
    program = command.program
    if program not in INTERPRETERS:
        return False
    if program in ("python", "python3") and trust_names:
        return not _python_reads_data(command.args)
    return True


@dataclass
class ShellCommand:
    """One parsed command within a pipeline."""

    argv: list[str]
    raw: str
    line: int

    @cached_property
    def effective(self) -> list[str]:
        """``argv`` with wrappers and leading assignments removed: what actually runs."""
        return unwrap(self.argv)

    @property
    def program(self) -> str:
        if not self.effective:
            return ""
        name = self.effective[0].rsplit("/", 1)[-1].removesuffix(".exe")
        return interpreter_name(name)

    @property
    def args(self) -> list[str]:
        return self.effective[1:]


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
    #: Code run from a repository cloned at an unpinned revision.
    clone_runs: list[CloneRun] = field(default_factory=list)


@dataclass(frozen=True)
class CloneRun:
    """``git clone URL dir`` followed by running something inside ``dir``."""

    url: str
    clone_line: int
    run: str
    run_line: int


#: ``git clone`` options that take a value, so the value is not the URL.
_CLONE_VALUE_OPTIONS = frozenset(
    {"-b", "--branch", "--depth", "-c", "--config", "-o", "--origin", "-j", "--jobs",
     "--reference", "--reference-if-able", "--template", "--separate-git-dir", "-u",
     "--upload-pack", "--filter", "--shallow-since", "--shallow-exclude", "--server-option",
     "--bundle-uri", "--revision"}
)
_REMOTE_URL = re.compile(r"^(?:https?|git|ssh)://|^[\w.-]+@[\w.-]+:")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
#: Commands that run the project in the current directory: its build file,
#: install hooks, or test runner execute code from the checkout.
_PROJECT_RUNNERS = frozenset(
    {("make", ""), ("npm", "install"), ("npm", "i"), ("npm", "ci"), ("npm", "run"),
     ("npm", "start"), ("npm", "test"), ("yarn", ""), ("yarn", "install"), ("yarn", "run"),
     ("pnpm", "install"), ("pnpm", "i"), ("pnpm", "run"), ("bun", "install"), ("bun", "run"),
     ("cargo", "run"), ("cargo", "build"), ("cargo", "install"), ("go", "run"),
     ("bundle", "install"), ("bundle", "exec"), ("rake", ""), ("gradle", ""), ("mvn", "")}
)
_PIP = frozenset({"pip", "pip3", "uv", "pipx"})


def _clone_target(args: list[str]) -> tuple[str, str] | None:
    """(url, directory) for ``git clone`` arguments, or None for a local clone."""
    positional: list[str] = []
    skip = False
    for arg in args[1:]:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = arg in _CLONE_VALUE_OPTIONS
            continue
        positional.append(arg)
    if not positional or not _REMOTE_URL.search(positional[0]):
        return None
    url = positional[0]
    if len(positional) > 1:
        directory = positional[1]
    else:
        directory = url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1].removesuffix(".git")
    return url, _norm(directory)


def _norm(path: str) -> str:
    path = path.strip()
    while path.startswith("./"):
        path = path[2:]
    return path.rstrip("/")


def _inside(path: str, directory: str) -> bool:
    path = _norm(path)
    return bool(directory) and (path == directory or path.startswith(directory + "/"))


def find_clone_runs(commands: list[ShellCommand]) -> list[CloneRun]:
    """Code from a fresh, unpinned clone that is then executed.

    The link is followed, not guessed: the command must run a path inside the
    cloned directory, or run the project after ``cd`` into it. A clone followed
    by an unrelated command is ordinary and is not reported, and neither is a
    clone pinned to a full commit hash before anything runs.
    """
    clones: dict[str, tuple[str, int]] = {}
    pinned: set[str] = set()
    here: str | None = None  # the clone the working directory is inside, if any
    found: list[CloneRun] = []
    for command in commands:
        program, args = command.program, command.args
        if program == "git" and args:
            target_dir = here
            if args[0] == "-C" and len(args) > 2:
                target_dir = next((d for d in clones if _inside(args[1], d)), None)
                args = args[2:]
            if args[0] == "clone":
                target = _clone_target(args)
                if target is not None:
                    clones[target[1]] = (target[0], command.line)
                    pinned.discard(target[1])
                    if any(a.startswith("--revision") and _FULL_SHA.match(a.split("=", 1)[-1])
                           for a in args):
                        pinned.add(target[1])
            elif args[0] in ("checkout", "switch", "reset") and target_dir is not None \
                    and any(_FULL_SHA.match(a) for a in args[1:]):
                pinned.add(target_dir)
            continue
        if program in ("cd", "pushd"):
            destination = args[0] if args else ""
            here = next((d for d in clones if _inside(destination, d)), None)
            continue
        directory = _executed_clone(command, clones, here)
        if directory is not None and directory not in pinned:
            url, clone_line = clones[directory]
            found.append(CloneRun(url, clone_line, command.raw[:160], command.line))
    return found


def _executed_clone(command: ShellCommand, clones: dict[str, tuple[str, int]], here: str | None) -> str | None:
    """The cloned directory whose code ``command`` runs, if any."""
    argv = command.effective
    program, args = command.program, command.args
    if not argv:
        return None

    def clone_of(path: str) -> str | None:
        return next((d for d in clones if _inside(path, d)), None)

    # A path to a file inside the clone, run directly, sourced, or handed to an interpreter.
    direct = clone_of(argv[0]) if "/" in argv[0] else None
    if direct is not None:
        return direct
    if program in INTERPRETERS or program in ("source", "."):
        script = next((a for a in args if not a.startswith("-")), "")
        if script and clone_of(script) is not None:
            return clone_of(script)
        if here is not None and script and not script.startswith("/") and (
            "." in script.rsplit("/", 1)[-1] or "/" in script
        ):
            return here
        return None
    # make -C dir, npm --prefix dir, pip install ./dir
    for flag in ("-C", "--prefix", "--cwd", "--manifest-path"):
        if flag in args:
            index = args.index(flag)
            if index + 1 < len(args) and clone_of(args[index + 1]) is not None:
                return clone_of(args[index + 1])
    if program in _PIP and "install" in args:
        for arg in args[args.index("install") + 1 :]:
            if arg.startswith("-"):
                continue
            if clone_of(arg) is not None:
                return clone_of(arg)
            if here is not None and _norm(arg) in ("", "."):
                return here
        return None
    if here is None:
        return None
    if argv[0].startswith("./"):
        return here
    first = args[0] if args else ""
    if (program, first) in _PROJECT_RUNNERS or (program, "") in _PROJECT_RUNNERS:
        return here
    if program in ("python", "python3") and first == "setup.py":
        return here
    return None


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


def parse_shell(
    text: str,
    path: str,
    *,
    start_line: int = 1,
    strip_comments: bool = True,
    trust_names: bool | None = None,
) -> ShellAnalysis:
    """Tokenise shell text and extract capability observations.

    ``trust_names`` says whether ``python`` here means Python; by default it is
    decided from ``text`` itself (see ``shadows_interpreters``). A caller
    parsing one block of a larger document passes the answer for the whole
    document, since a function defined in one block applies in the next.
    """
    analysis = ShellAnalysis(path=path)
    source = _strip_comments(text) if strip_comments else text
    if trust_names is None:
        trust_names = not shadows_interpreters(text)

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
        _analyse_pipeline(analysis, parsed, raw_line, line_no, trust_names)

    analysis.clone_runs = find_clone_runs(analysis.commands)
    return analysis


def _analyse_pipeline(
    analysis: ShellAnalysis,
    commands: list[ShellCommand],
    raw_line: str,
    line_no: int,
    trust_names: bool = True,
) -> None:
    # curl … | bash  (and the wget/nc equivalents). Only a downstream command
    # that runs its input counts: `curl … | python3 -m json.tool` prints it.
    piped = has_unquoted_pipe(raw_line)
    for index, command in enumerate(commands):
        program = command.program
        if not piped or program not in NETWORK_FETCHERS | {"base64", "xxd", "openssl", "uudecode"}:
            continue
        downstream = commands[index + 1 :]
        if not any(executes_stdin(c, trust_names=trust_names) for c in downstream):
            continue
        if program in NETWORK_FETCHERS:
            analysis.fetch_to_interpreter.append((raw_line.strip()[:160], line_no))
        else:
            analysis.decode_to_interpreter.append((raw_line.strip()[:160], line_no))

    for command in commands:
        program = command.program
        excerpt = command.raw[:160]
        args = command.args

        def observe(
            capability: Capability,
            detail: str,
            confidence: Confidence = Confidence.HIGH,
            # Bound as defaults rather than captured: the closure is only called
            # within this iteration today, but a late-bound `excerpt` would
            # silently attach the wrong command to the evidence if that changed.
            _excerpt: str = excerpt,
            _line: int = line_no,
        ) -> None:
            analysis.observations.append(
                Observation(
                    capability=capability,
                    source=Source.CODE,
                    confidence=confidence,
                    evidence=Evidence(path=analysis.path, line=_line, excerpt=_excerpt),
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
