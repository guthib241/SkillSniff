"""JavaScript and TypeScript analysis, by tokenising rather than parsing.

There is no JavaScript parser in the standard library, and this tool takes no
runtime dependencies. For security analysis what matters most is knowing where
code is *not*: a pattern inside a string, a template literal, a comment or a
regular expression is text, not an instruction. This tokeniser knows those
boundaries, and the analysis reads the resulting token stream, the same job
the shell tokeniser does for scripts.

It covers what the Python AST pass covers, at lower fidelity:

* commands run through a shell (``child_process.exec``, ``spawn`` with
  ``shell: true`` or ``sh -c``, shelljs, zx);
* code built and evaluated at runtime (``eval``, ``new Function``, ``vm``);
* a secret flowing from the environment, or a credential file, into a network
  call, a socket, or a shelled-out ``curl``, with the same exception as the
  Python rule for a credential sent as an authentication header to a fixed
  endpoint;
* credential files read with ``fs``.

It does not resolve imports across files, follow values through function
calls, or understand types. Names are tracked per file, in source order.

Every stage is linear in the size of the file. A scan that is quadratic in its
input is a denial-of-service an attacker can trigger for free, and this project
has shipped one before. Where a bounded window would let padding hide a flow,
the bound is on total work instead, and running out is reported as a coverage
gap rather than silently skipped.
"""

from __future__ import annotations

import heapq
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field

from skillsniff.analysis.pyast import TaintFlow, is_secret_name
from skillsniff.analysis.shell import CREDENTIAL_PATHS
from skillsniff.model.capability import Capability, Observation, Source
from skillsniff.model.finding import Confidence, Evidence

#: Suffixes analysed as JavaScript or TypeScript.
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"})

#: Characters handed to the tokeniser: the bound the pattern scanners use.
MAX_JS_CHARS = 1 << 20
#: Taint flows recorded per file. The rules cite a handful; the cap bounds work.
MAX_FLOWS = 50
#: Observations kept per capability per file: enough to cite, bounded in size.
MAX_OBSERVATIONS = 25
#: Longest dotted callee followed backwards from a call.
_MAX_CHAIN = 16
#: Tokens of an argument list or object literal read when classifying a call.
_WINDOW = 1024

_REGEX_AFTER_KEYWORD = frozenset(
    {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
     "case", "do", "else", "yield", "await"}
)
#: After these, a newline does not end the expression.
_CONTINUES = frozenset(
    {".", "op", "+", "-", "*", "/", "%", "&", "|", "^", "?", ":", "=>", "<", ">", ",", ";", "="}
)
_NO_END_KEYWORDS = frozenset({"await", "new", "typeof", "void", "delete", "yield", "return"})
_DECLARATION = frozenset({"const", "let", "var"})
_MODIFIERS = frozenset({"private", "public", "protected", "readonly", "static", "declare", "override"})
_OPEN = ("(", "[", "{")
_CLOSE = (")", "]", "}")

#: A destination whose host is settled: ``scheme://host[:port]`` then a path.
_FIXED_HOST = re.compile(r"^[A-Za-z][\w+.-]*://[^/\s?#'\"`]+[/?#]")
_NET_COMMAND = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|ftp|telnet|"
    r"Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b"
)
#: The text before an interpolation, when it puts the value in a request header.
_HEADER_CONTEXT = re.compile(
    r"(?:-H|--header)\s+[\"']?[\w-]+:\s*(?:Bearer\s+|token\s+|Basic\s+)?$", re.IGNORECASE
)


@dataclass(slots=True)
class Token:
    kind: str  # "ident" | "string" | "number" | "punct" | "regex"
    value: str
    line: int
    #: For a template literal: whether it contains a ``${…}`` interpolation.
    interpolated: bool = False
    #: Whether the string was written with backticks.
    template: bool = False
    #: For a template: its literal text segments, one more than its interpolations.
    segments: list[str] | None = None
    #: For a template: the token index where each interpolation's tokens begin.
    holes: list[int] | None = None
    #: For a template: the index one past the last token of its interpolations.
    span_end: int = -1


def _regex_allowed(out: list[Token]) -> bool:
    if not out:
        return True
    prev = out[-1]
    if prev.kind == "punct":
        return prev.value not in _CLOSE
    if prev.kind == "ident":
        return prev.value in _REGEX_AFTER_KEYWORD
    return False


def tokenize(text: str) -> list[Token]:
    """Split JavaScript into tokens, dropping comments. Linear; never raises."""
    text = text[:MAX_JS_CHARS]
    out: list[Token] = []
    n = len(text)
    i = 0
    line = 1
    #: For each open ``${`` expression, the depth of ordinary braces inside it.
    braces: list[int] = []
    #: Index into ``out`` of each template literal still being read.
    templates: list[int] = []
    in_template_text = False
    #: End of a line on which a regular expression failed to close. Before it a
    #: ``/`` is division: rescanning from every slash would be quadratic.
    regex_dead_until = -1

    if text.startswith("#!"):
        newline = text.find("\n")
        i = n if newline == -1 else newline

    while i < n:
        if in_template_text:
            current = out[templates[-1]]
            assert current.segments is not None and current.holes is not None
            start = i
            left = False
            while i < n:
                ch = text[i]
                if ch == "\\":
                    if i + 1 < n and text[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if ch == "\n":
                    line += 1
                    i += 1
                    continue
                if ch == "`":
                    current.segments[-1] += text[start:i]
                    current.value = "".join(current.segments)
                    current.span_end = len(out)
                    templates.pop()
                    in_template_text = False
                    i += 1
                    left = True
                    break
                if ch == "$" and i + 1 < n and text[i + 1] == "{":
                    current.segments[-1] += text[start:i]
                    current.segments.append("")
                    current.holes.append(len(out))
                    current.interpolated = True
                    braces.append(0)
                    in_template_text = False
                    i += 2
                    left = True
                    break
                i += 1
            if not left:
                current.segments[-1] += text[start:i]
                current.value = "".join(current.segments)
            continue

        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in " \t\r\f\v":
            i += 1
            continue

        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                end = text.find("\n", i)
                i = n if end == -1 else end
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                stop = n if end == -1 else end + 2
                line += text.count("\n", i, stop)
                i = stop
                continue
            if i > regex_dead_until and _regex_allowed(out):
                j = i + 1
                in_class = False
                closed = False
                while j < n:
                    c = text[j]
                    if c == "\\":
                        j += 2
                        continue
                    if c == "\n":
                        break
                    if c == "[":
                        in_class = True
                    elif c == "]":
                        in_class = False
                    elif c == "/" and not in_class:
                        closed = True
                        break
                    j += 1
                if closed:
                    j += 1
                    while j < n and text[j].isalpha():
                        j += 1
                    out.append(Token("regex", text[i:j], line))
                    i = j
                    continue
                regex_dead_until = j

        if ch in "'\"":
            j = i + 1
            while j < n:
                c = text[j]
                if c == "\\":
                    if j + 1 < n and text[j + 1] == "\n":
                        line += 1
                    j += 2
                    continue
                if c == ch or c == "\n":
                    break
                j += 1
            out.append(Token("string", text[i + 1 : min(j, n)], line))
            i = j + 1 if j < n and text[j] == ch else j
            continue

        if ch == "`":
            out.append(Token("string", "", line, template=True, segments=[""], holes=[]))
            templates.append(len(out) - 1)
            in_template_text = True
            i += 1
            continue

        if ch.isalpha() or ch in "_$":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            out.append(Token("ident", text[i:j], line))
            i = j
            continue

        if ch.isdigit():
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_."):
                j += 1
            out.append(Token("number", text[i:j], line))
            i = j
            continue

        if ch == "{":
            if braces:
                braces[-1] += 1
            out.append(Token("punct", "{", line))
            i += 1
            continue
        if ch == "}":
            if braces:
                if braces[-1] == 0:
                    braces.pop()
                    in_template_text = True
                    i += 1
                    continue
                braces[-1] -= 1
            out.append(Token("punct", "}", line))
            i += 1
            continue

        if text.startswith("?.", i) and not (i + 2 < n and text[i + 2].isdigit()):
            out.append(Token("punct", ".", line))
            i += 2
            continue
        if text.startswith("...", i):
            out.append(Token("punct", "...", line))
            i += 3
            continue
        if text.startswith("=>", i):
            out.append(Token("punct", "=>", line))
            i += 2
            continue
        if ch in "=!<>+-*%&|^" and i + 1 < n and text[i + 1] == "=":
            j = i + 2
            if j < n and text[j] == "=":
                j += 1
            out.append(Token("punct", "op", line))  # comparison or compound assignment
            i = j
            continue

        out.append(Token("punct", ch, line))
        i += 1

    for index in templates:  # unterminated at end of input
        unterminated = out[index]
        unterminated.span_end = len(out)
        if unterminated.segments is not None:
            unterminated.value = "".join(unterminated.segments)
    return out


def pair_brackets(tokens: list[Token]) -> list[int]:
    """For each bracket, the index of its partner; -1 where there is none."""
    pair = [-1] * len(tokens)
    stack: list[int] = []
    for i, tok in enumerate(tokens):
        if tok.kind != "punct":
            continue
        if tok.value in _OPEN:
            stack.append(i)
        elif tok.value in _CLOSE and stack:
            j = stack.pop()
            pair[j] = i
            pair[i] = j
    return pair


# ---------------------------------------------------------------------------
# What the analysis recognises
# ---------------------------------------------------------------------------

#: Calls that always run their command through a shell.
_SHELL_CALLS = frozenset({"child_process.exec", "child_process.execSync", "shelljs.exec"})
#: Calls that run a program, and use a shell only when told to.
_PROC_CALLS = frozenset(
    {"child_process.spawn", "child_process.spawnSync", "child_process.execFile",
     "child_process.execFileSync", "child_process.fork", "execa", "execa.execa",
     "execa.execaSync", "execa.execaCommand", "execa.execaCommandSync", "cross-spawn",
     "cross-spawn.sync", "Bun.spawn", "Bun.spawnSync", "Deno.run", "Deno.Command"}
)
#: Tagged templates that run their text as a shell command.
_SHELL_TAGS = frozenset({"zx.$", "execa.$", "Bun.$"})
_SHELL_PROGRAMS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/zsh",
     "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
)
_SHELL_FLAGS = frozenset({"-c", "-lc", "-ic", "/c", "/C", "-Command", "-command"})
_EVAL_CALLS = frozenset({"eval", "window.eval", "globalThis.eval", "global.eval", "self.eval"})
_FUNCTION_CTORS = frozenset({"Function", "window.Function", "globalThis.Function", "global.Function"})
_VM_EVAL = frozenset(
    {"vm.runInNewContext", "vm.runInThisContext", "vm.runInContext", "vm.compileFunction",
     "vm.Script", "vm.SourceTextModule"}
)
_TIMERS = frozenset({"setTimeout", "setInterval", "window.setTimeout", "window.setInterval"})

#: Network calls and the direction each implies, mirroring the Python table.
_NET_CALLS: dict[str, tuple[Capability, ...]] = {
    "fetch": (Capability.NET_FETCH,),
    "window.fetch": (Capability.NET_FETCH,),
    "globalThis.fetch": (Capability.NET_FETCH,),
    "node-fetch": (Capability.NET_FETCH,),
    "cross-fetch": (Capability.NET_FETCH,),
    "undici.fetch": (Capability.NET_FETCH,),
    "undici.request": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "axios": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "axios.request": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "axios.get": (Capability.NET_FETCH,),
    "axios.head": (Capability.NET_FETCH,),
    "axios.post": (Capability.NET_OUTBOUND,),
    "axios.put": (Capability.NET_OUTBOUND,),
    "axios.patch": (Capability.NET_OUTBOUND,),
    "axios.delete": (Capability.NET_OUTBOUND,),
    "http.request": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "https.request": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "http.get": (Capability.NET_FETCH,),
    "https.get": (Capability.NET_FETCH,),
    "got": (Capability.NET_FETCH,),
    "got.get": (Capability.NET_FETCH,),
    "got.post": (Capability.NET_OUTBOUND,),
    "got.put": (Capability.NET_OUTBOUND,),
    "got.patch": (Capability.NET_OUTBOUND,),
    "request": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "request.get": (Capability.NET_FETCH,),
    "request.post": (Capability.NET_OUTBOUND,),
    "superagent.post": (Capability.NET_OUTBOUND,),
    "needle.post": (Capability.NET_OUTBOUND,),
    "navigator.sendBeacon": (Capability.NET_OUTBOUND,),
    "WebSocket": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "ws": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "ws.WebSocket": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "XMLHttpRequest": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "net.connect": (Capability.NET_OUTBOUND,),
    "net.createConnection": (Capability.NET_OUTBOUND,),
    "tls.connect": (Capability.NET_OUTBOUND,),
    "dgram.createSocket": (Capability.NET_OUTBOUND,),
    "dns.resolve": (Capability.NET_DNS,),
    "dns.resolve4": (Capability.NET_DNS,),
    "dns.resolveTxt": (Capability.NET_DNS,),
    "dns.lookup": (Capability.NET_DNS,),
    "dns.promises.resolve": (Capability.NET_DNS,),
    "dns.promises.lookup": (Capability.NET_DNS,),
    "dns/promises.resolve": (Capability.NET_DNS,),
    "dns/promises.lookup": (Capability.NET_DNS,),
    "nodemailer.createTransport": (Capability.NET_OUTBOUND,),
}
#: Requests whose method decides the direction.
_FETCH_LIKE = frozenset(
    {"fetch", "window.fetch", "globalThis.fetch", "node-fetch", "cross-fetch", "undici.fetch"}
)
#: Calls returning an object whose write/send/end transmits data.
_CHANNELS = frozenset(
    {"http.request", "https.request", "net.connect", "net.createConnection", "tls.connect",
     "WebSocket", "ws", "ws.WebSocket", "XMLHttpRequest", "dgram.createSocket",
     "nodemailer.createTransport"}
)
_CHANNEL_SENDS = frozenset({"write", "end", "send", "sendMail"})
#: Calls whose second positional argument is the request body.
_POSITIONAL_BODY = frozenset(
    {"axios.post", "axios.put", "axios.patch", "navigator.sendBeacon", "request.post"}
)
_SENDING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_FS_READ = frozenset(
    {"fs.readFile", "fs.readFileSync", "fs.createReadStream", "fs.copyFile", "fs.copyFileSync",
     "fs.readdir", "fs.readdirSync", "fs.promises.readFile", "fs.promises.copyFile",
     "fs/promises.readFile", "fs/promises.copyFile", "fs/promises.readdir",
     "fs-extra.readFile", "fs-extra.readFileSync", "fs-extra.readJson", "fs-extra.readJsonSync",
     "fs-extra.copy", "fs-extra.copySync", "Bun.file", "Deno.readTextFile", "Deno.readFile"}
)
_FS_WRITE = frozenset(
    {"fs.writeFile", "fs.writeFileSync", "fs.appendFile", "fs.appendFileSync",
     "fs.createWriteStream", "fs.promises.writeFile", "fs.promises.appendFile",
     "fs/promises.writeFile", "fs/promises.appendFile", "fs-extra.writeFile",
     "fs-extra.writeFileSync", "fs-extra.outputFile", "fs-extra.writeJson", "Bun.write",
     "Deno.writeTextFile"}
)
#: Calls that hand back a request's result: the response is not the secret.
_PASS_THROUGH = frozenset({"util.promisify", "promisify"})
#: Keys whose value is authentication, in a request's options or its headers.
_AUTH_KEYS = frozenset(
    {"headers", "auth", "authorization", "proxy-authorization", "x-api-key", "api-key",
     "x-auth-token", "x-access-token", "private-token", "x-goog-api-key", "cookie"}
)
#: Keys whose value is the request body: a secret here is payload, never authentication.
_PAYLOAD_KEYS = frozenset(
    {"body", "data", "json", "form", "formdata", "payload", "message", "text", "html",
     "content", "attachments", "params", "query", "searchparams", "qs"}
)
#: Keys naming a request's destination in an options object.
_DESTINATION_KEYS = frozenset({"url", "uri", "href", "hostname", "host", "baseurl", "service"})
#: Mutating calls that put a value into the container they are called on.
_CONTAINER_WRITES = frozenset({"push", "unshift", "set", "append", "add", "assign"})
#: Modules whose import alone says something about capability.
_IMPORT_CAPABILITIES: dict[str, tuple[Capability, ...]] = {
    "child_process": (Capability.PROC_EXEC,),
    "execa": (Capability.PROC_EXEC,),
    "cross-spawn": (Capability.PROC_EXEC,),
    "shelljs": (Capability.SHELL_EXEC,),
    "zx": (Capability.SHELL_EXEC,),
    "node-pty": (Capability.SHELL_EXEC,),
    "keytar": (Capability.SECRET_ACCESS,),
}


@dataclass(slots=True)
class Origin:
    """Where a tainted value came from."""

    source: str
    line: int
    variable: str
    #: The secret was only ever placed in an authentication position.
    auth_only: bool = False
    #: The value is the whole environment, so ``env.PORT`` is not a secret.
    whole_env: bool = False


@dataclass
class JsAnalysis:
    path: str
    observations: list[Observation] = field(default_factory=list)
    modules: set[str] = field(default_factory=set)
    #: (callee, line) for commands that go through a shell.
    shell_exec: list[tuple[str, int]] = field(default_factory=list)
    #: (callee, line) for code constructed and evaluated at runtime.
    dynamic_eval: list[tuple[str, int]] = field(default_factory=list)
    taint_flows: list[TaintFlow] = field(default_factory=list)
    #: (path literal, line) for credential files passed to a read.
    credential_paths: list[tuple[str, int]] = field(default_factory=list)
    #: Why the analysis stopped short of the whole file, or "" when it did not.
    truncated: str = ""


class _TaintIndex:
    """Which currently-tainted name first occurs in a range of tokens.

    Queries arrive in increasing order of their start, because the analysis
    reads the file once from the top. That lets each tainted name keep a
    pointer into its own occurrence list, with a heap over the pointers, so a
    query costs a logarithm rather than a scan of the range. The whole-file
    cost is proportional to the number of occurrences, however the code is
    shaped.
    """

    def __init__(self, plain: dict[str, list[int]], members: dict[str, list[int]]) -> None:
        #: Occurrences used as a value, or followed by a secret-shaped member.
        self.plain = plain
        #: Occurrences followed by a member whose name is not secret-shaped.
        self.members = members
        self.tainted: dict[str, Origin] = {}
        self._version: dict[str, int] = {}
        self._heap: list[tuple[int, int, str, int]] = []

    def _lists(self, which: int) -> dict[str, list[int]]:
        return self.plain if which == 0 else self.members

    def _push(self, key: str, version: int, which: int, at: int, *, right: bool) -> None:
        occurrences = self._lists(which).get(key)
        if not occurrences:
            return
        p = bisect_right(occurrences, at) if right else bisect_left(occurrences, at)
        if p < len(occurrences):
            heapq.heappush(self._heap, (occurrences[p], version, key, which))

    def add(self, key: str, origin: Origin, at: int) -> None:
        version = self._version.get(key, 0) + 1
        self._version[key] = version
        self.tainted[key] = origin
        self._push(key, version, 0, at, right=True)
        if not origin.whole_env:
            self._push(key, version, 1, at, right=True)

    def clear(self, key: str) -> None:
        if key in self.tainted:
            del self.tainted[key]
            self._version[key] = self._version.get(key, 0) + 1

    def first_in(self, lo: int, hi: int) -> tuple[int, str] | None:
        heap = self._heap
        while heap:
            index, version, key, which = heap[0]
            if self._version.get(key) != version or key not in self.tainted:
                heapq.heappop(heap)
                continue
            if index < lo:
                heapq.heappop(heap)
                self._push(key, version, which, lo, right=False)
                continue
            break
        if heap and heap[0][0] < hi:
            return heap[0][0], heap[0][2]
        return None


def _module_name(raw: str) -> str:
    name = raw.strip()
    return name[len("node:") :] if name.startswith("node:") else name


def _inside(spans: list[tuple[int, int]], i: int) -> bool:
    return any(lo <= i < hi for lo, hi in spans)


class _Reader:
    def __init__(self, path: str, tokens: list[Token], *, zx: bool) -> None:
        self.path = path
        self.t = tokens
        self.n = len(tokens)
        self.pair = pair_brackets(tokens)
        self.result = JsAnalysis(path=path)
        self.zx = zx
        #: local name -> dotted module path, e.g. "cp" -> "child_process".
        self.aliases: dict[str, str] = {}
        #: Names bound to a fully literal string, with its value.
        self.literals: dict[str, str] = {}
        #: Names bound to a destination whose host is fixed, or user-configured.
        self.fixed: set[str] = set()
        #: Names bound to a socket, request, or mail transport.
        self.channels: dict[str, str] = {}
        #: Every plain name assigned in this file, so constants are not assumed.
        self.assigned: set[str] = set()
        #: Names bound to a value containing a credential-file path.
        self.credential_names: dict[str, tuple[str, int]] = {}
        #: Token index -> description, for secret sources visible in the text itself.
        self.static: dict[int, str] = {}
        #: Token index -> literal, for credential-file paths.
        self.credential_at: dict[int, str] = {}
        self.next_static: list[int] = []
        self.next_credential: list[int] = []
        self.rhs_end: dict[int, int] = {}
        self._observed: dict[Capability, int] = {}
        self.work = 0
        self.work_limit = 16 * self.n + 100_000
        plain, members = self._index()
        self.taint = _TaintIndex(plain, members)
        self._compute_rhs_ends()

    # -- small helpers --------------------------------------------------------

    def tok(self, k: int) -> Token | None:
        return self.t[k] if 0 <= k < self.n else None

    def punct(self, k: int, value: str) -> bool:
        tok = self.tok(k)
        return tok is not None and tok.kind == "punct" and tok.value == value

    def ident(self, k: int, value: str | None = None) -> bool:
        tok = self.tok(k)
        return tok is not None and tok.kind == "ident" and (value is None or tok.value == value)

    def spend(self, amount: int) -> bool:
        """Charge ``amount`` tokens of optional work; False once the budget is spent."""
        self.work += amount
        if self.work > self.work_limit:
            if not self.result.truncated:
                self.result.truncated = "work budget exhausted; later calls were not classified"
            return False
        return True

    def close_of(self, k: int) -> int:
        partner = self.pair[k]
        return partner if partner > k else self.n

    def observe(self, capability: Capability, line: int, excerpt: str, detail: str,
                confidence: Confidence = Confidence.HIGH) -> None:
        count = self._observed.get(capability, 0)
        if count >= MAX_OBSERVATIONS:
            return
        self._observed[capability] = count + 1
        self.result.observations.append(
            Observation(
                capability=capability,
                source=Source.CODE,
                confidence=confidence,
                evidence=Evidence(path=self.path, line=line, excerpt=excerpt[:120]),
                detail=detail,
            )
        )

    def _is_key(self, i: int) -> bool:
        """``{ key: …`` or ``, key: …``: a property name, not a reference."""
        return self.punct(i + 1, ":") and (self.punct(i - 1, "{") or self.punct(i - 1, ","))

    def _skip_value(self, j: int, hi: int) -> int:
        """End of the expression starting at ``j``: the next top-level comma or closer."""
        while j < hi:
            tok = self.t[j]
            if tok.kind == "punct":
                if tok.value in _OPEN:
                    partner = self.pair[j]
                    j = partner + 1 if partner > j else hi
                    continue
                if tok.value in _CLOSE or tok.value == ",":
                    return j
            j += 1
        return hi

    # -- pass 0: index ----------------------------------------------------------

    def _index(self) -> tuple[dict[str, list[int]], dict[str, list[int]]]:
        t = self.t
        plain: dict[str, list[int]] = {}
        members: dict[str, list[int]] = {}
        for i, tok in enumerate(t):
            if tok.kind == "string":
                if CREDENTIAL_PATHS.search(tok.value):
                    self.credential_at[i] = tok.value
                    self.static[i] = f"credential file {tok.value[:60]!r}"
                continue
            if tok.kind != "ident" or self.punct(i - 1, "."):
                continue
            value = tok.value
            if value == "this":
                if self.punct(i + 1, ".") and self.ident(i + 2):
                    plain.setdefault(f"this.{t[i + 2].value}", []).append(i)
                continue
            if self._is_key(i):
                continue
            if value in ("process", "Bun", "Deno"):
                self._env_source(i)
            member = t[i + 2] if self.punct(i + 1, ".") and self.ident(i + 2) else None
            if member is not None and not is_secret_name(member.value):
                members.setdefault(value, []).append(i)
            else:
                plain.setdefault(value, []).append(i)

        nearest = self.n
        self.next_static = [self.n] * (self.n + 1)
        for i in range(self.n - 1, -1, -1):
            if i in self.static:
                nearest = i
            self.next_static[i] = nearest
        nearest = self.n
        self.next_credential = [self.n] * (self.n + 1)
        for i in range(self.n - 1, -1, -1):
            if i in self.credential_at:
                nearest = i
            self.next_credential[i] = nearest
        return plain, members

    def _env_source(self, i: int) -> None:
        """Record ``process.env…`` (or Bun's, or Deno's) starting at ``i``."""
        t = self.t
        head = t[i].value
        if not (self.punct(i + 1, ".") and self.ident(i + 2, "env")):
            return
        line = t[i].line
        name: str | None = None
        if self.punct(i + 3, ".") and self.ident(i + 4):
            name = t[i + 4].value
            if head == "Deno" and name == "get" and self.punct(i + 5, "(") \
                    and (s := self.tok(i + 6)) is not None and s.kind == "string":
                name = s.value
            elif head == "Deno" and name == "toObject":
                name = None
        elif self.punct(i + 3, "["):
            s = self.tok(i + 4)
            if s is not None and s.kind == "string" and not s.interpolated and self.punct(i + 5, "]"):
                name = s.value
            else:
                self.static[i] = f"{head}.env[…]"
                self.observe(Capability.ENV_READ, line, f"{head}.env[…]",
                             "reads an environment variable chosen at runtime")
                return
        if name is None:
            self.static[i] = f"{head}.env"
            self.observe(Capability.ENV_READ, line, f"{head}.env", "reads the whole environment")
            return
        self.observe(Capability.ENV_READ, line, f"{head}.env.{name}",
                     f"reads environment variable {name!r}")
        if is_secret_name(name):
            self.static[i] = f"{head}.env.{name}"
            self.observe(Capability.CREDENTIAL_HANDLING, line, f"{head}.env.{name}",
                         f"{name} is a credential-shaped variable name")

    def _compute_rhs_ends(self) -> None:
        """For each ``=``, where its right-hand side ends. One pass, a stack of frames."""
        t = self.t
        frames: list[list[int]] = [[]]
        prev: Token | None = None
        for i, tok in enumerate(t):
            pending = frames[-1]
            if prev is not None and pending and tok.line != prev.line and self._ends(prev, tok):
                for k in pending:
                    self.rhs_end[k] = i
                pending.clear()
            if tok.kind == "punct":
                value = tok.value
                if value in _OPEN:
                    frames.append([])
                elif value in _CLOSE:
                    for k in frames[-1]:
                        self.rhs_end[k] = i
                    if len(frames) > 1:
                        frames.pop()
                    else:
                        frames[-1].clear()
                elif value in (";", ","):
                    for k in pending:
                        self.rhs_end[k] = i
                    pending.clear()
                elif value == "=":
                    pending.append(i)
            prev = tok
        for frame in frames:
            for k in frame:
                self.rhs_end[k] = self.n

    @staticmethod
    def _ends(prev: Token, tok: Token) -> bool:
        """Whether a newline between ``prev`` and ``tok`` ends a statement."""
        if prev.kind == "punct":
            if prev.value not in _CLOSE:
                return False
        elif prev.kind == "ident" and prev.value in _NO_END_KEYWORDS:
            return False
        if tok.kind == "punct" and tok.value in _CONTINUES:
            return False
        return not (tok.kind == "string" and tok.template)

    # -- taint lookups ----------------------------------------------------------

    def first_taint(self, lo: int, hi: int) -> Origin | None:
        """The first secret in ``t[lo:hi]``. Calls must arrive with ``lo`` increasing."""
        if lo >= hi:
            return None
        static = self.next_static[lo]
        dynamic = self.taint.first_in(lo, hi)
        if static < hi and (dynamic is None or static <= dynamic[0]):
            return self._static_origin(static)
        if dynamic is not None:
            return self.taint.tainted[dynamic[1]]
        return None

    def _static_origin(self, i: int) -> Origin:
        desc = self.static[i]
        variable = desc.split(".env.", 1)[1] if ".env." in desc else desc
        return Origin(source=desc, line=self.t[i].line, variable=variable,
                      whole_env=desc.endswith(".env"))

    def taint_at(self, i: int) -> Origin | None:
        """The taint carried by the token at ``i``, by the current state."""
        if i in self.static:
            return self._static_origin(i)
        tok = self.t[i]
        if tok.kind != "ident" or self.punct(i - 1, ".") or self._is_key(i):
            return None
        if tok.value == "this":
            if not (self.punct(i + 1, ".") and self.ident(i + 2)):
                return None
            return self.taint.tainted.get(f"this.{self.t[i + 2].value}")
        origin = self.taint.tainted.get(tok.value)
        if origin is not None and origin.whole_env and self.punct(i + 1, ".") and self.ident(i + 2) \
                and not is_secret_name(self.t[i + 2].value):
            return None
        return origin

    # -- the single forward pass ------------------------------------------------

    def run(self) -> JsAnalysis:
        t = self.t
        for i, tok in enumerate(t):
            if tok.kind == "punct":
                if tok.value == "=":
                    self._assign(i)
                elif tok.value == "(":
                    self._call(i)
            elif tok.kind == "ident":
                if tok.value == "import" and not self.punct(i - 1, ".") and not self.punct(i + 1, "("):
                    self._import_statement(i)
                elif tok.value == "of":
                    self._for_of(i)
            elif tok.kind == "string" and tok.template and i > 0:
                self._tagged_template(i)
        return self.result

    def add_module(self, raw: str, line: int) -> str:
        module = _module_name(raw)
        if module not in self.result.modules:
            self.result.modules.add(module)
            for capability in _IMPORT_CAPABILITIES.get(module, ()):
                self.observe(capability, line, f"import {module}", f"imports {module}",
                             Confidence.MEDIUM)
        return module

    # -- imports ------------------------------------------------------------------

    def _import_statement(self, k: int) -> None:
        t = self.t
        j = k + 1
        first = self.tok(j)
        if first is None:
            return
        if first.kind == "string":
            self.add_module(first.value, first.line)
            return
        if self.ident(j, "type") and not (self.punct(j + 1, ",") or self.ident(j + 1, "from")):
            return  # a TypeScript type-only import binds nothing at runtime
        bindings: list[tuple[str, str | None]] = []
        for _ in range(8):
            tok = self.tok(j)
            if tok is None:
                return
            if tok.kind == "ident" and tok.value == "from":
                source = self.tok(j + 1)
                if source is None or source.kind != "string":
                    return
                module = self.add_module(source.value, source.line)
                for local, imported in bindings:
                    self.aliases[local] = module if imported is None else f"{module}.{imported}"
                if module == "zx":
                    self.zx = True
                return
            if tok.kind == "punct" and tok.value == "*" and self.ident(j + 1, "as") and self.ident(j + 2):
                bindings.append((t[j + 2].value, None))
                j += 3
                continue
            if tok.kind == "punct" and tok.value == "{":
                close = self.close_of(j)
                q = j + 1
                while q < close:
                    name = t[q]
                    if name.kind == "ident" and name.value != "type":
                        if self.ident(q + 1, "as") and self.ident(q + 2):
                            bindings.append((t[q + 2].value, name.value))
                            q += 3
                            continue
                        bindings.append((name.value, name.value))
                    q += 1
                j = close + 1
                continue
            if tok.kind == "punct" and tok.value == ",":
                j += 1
                continue
            if tok.kind == "ident":
                bindings.append((tok.value, None))  # default import
                j += 1
                continue
            return

    def _required_module(self, h: int, hi: int) -> str | None:
        """``require("m")`` or ``import("m")`` at ``h``, with any ``.member`` chain after it."""
        t = self.t
        if not ((self.ident(h, "require") or self.ident(h, "import")) and self.punct(h + 1, "(")):
            return None
        s = self.tok(h + 2)
        if s is None or s.kind != "string" or s.interpolated or not self.punct(h + 3, ")"):
            return None
        module = self.add_module(s.value, s.line)
        j = h + 4
        while j + 1 < hi and self.punct(j, ".") and self.ident(j + 1):
            module = f"{module}.{t[j + 1].value}"
            j += 2
        return module

    # -- assignments ----------------------------------------------------------------

    def _targets(self, k: int) -> list[tuple[str, str | None]]:
        """What the ``=`` at ``k`` assigns to: (local name, property it came from)."""
        t = self.t
        prev = self.tok(k - 1)
        if prev is None:
            return []
        if prev.kind == "ident":
            if self.punct(k - 2, "."):
                if self.ident(k - 3, "this") and not self.punct(k - 4, "."):
                    return [(f"this.{prev.value}", None)]
                return []
            if self.punct(k - 2, ":") and self.ident(k - 3):
                return [(t[k - 3].value, None)]  # TypeScript: name: Type = …
            return [(prev.value, None)]
        if prev.kind == "punct" and prev.value in ("}", "]"):
            opener = self.pair[k - 1]
            if opener < 0:
                return []
            before = self.tok(opener - 1)
            pattern = before is None or (before.kind == "ident" and before.value in _DECLARATION) \
                or (before.kind == "punct" and before.value in ("(", ",", ";", "{", "}"))
            if pattern:
                return self._pattern(opener, k - 1)
            return self._annotated(k)
        if prev.kind == "punct" and prev.value == ">":
            return self._annotated(k)
        return []

    def _annotated(self, k: int) -> list[tuple[str, str | None]]:
        """``name: Some<Type>[] = …``: walk back to the annotation's colon."""
        for j in range(k - 2, max(-1, k - 33), -1):
            tok = self.t[j]
            if tok.kind == "punct" and tok.value in ("=", ";"):
                return []
            if tok.kind == "punct" and tok.value == ":" and self.ident(j - 1):
                before = self.tok(j - 2)
                if before is None or (before.kind == "ident" and (
                        before.value in _DECLARATION or before.value in _MODIFIERS)) \
                        or (before.kind == "punct" and before.value in ("(", ",", ";", "{", "}")):
                    return [(self.t[j - 1].value, None)]
                return []
        return []

    def _pattern(self, opener: int, closer: int) -> list[tuple[str, str | None]]:
        """The names a destructuring pattern binds, each with the key it reads."""
        t = self.t
        out: list[tuple[str, str | None]] = []
        array = t[opener].value == "["
        j = opener + 1
        while j < closer and len(out) < 64:
            tok = t[j]
            if tok.kind == "punct" and tok.value in _OPEN:
                j = self.close_of(j) + 1  # nested patterns are not followed
                continue
            if tok.kind == "ident":
                if self.punct(j + 1, ":") and not array:
                    if self.ident(j + 2):
                        out.append((t[j + 2].value, tok.value))
                    j += 3
                    continue
                if self.punct(j - 1, "...") or array:
                    out.append((tok.value, None))
                elif self.punct(j - 1, "{") or self.punct(j - 1, ","):
                    out.append((tok.value, tok.value))
            j += 1
        return out

    def _head(self, lo: int, hi: int) -> int:
        """The first meaningful token of an expression, past ``await``, ``new`` and parens."""
        h = lo
        while h < hi:
            tok = self.t[h]
            if tok.kind == "ident" and tok.value in ("await", "new", "void"):
                h += 1
                continue
            if tok.kind == "punct" and tok.value == "(" and self.close_of(h) >= hi - 1:
                h += 1
                continue
            break
        return h

    def _chain(self, h: int, hi: int) -> tuple[str, int] | None:
        """``a.b.c`` starting at ``h``: (resolved dotted name, index after it)."""
        if not self.ident(h):
            return None
        parts = [self.t[h].value]
        j = h + 1
        while j + 1 < hi and self.punct(j, ".") and self.ident(j + 1) and len(parts) < _MAX_CHAIN:
            parts.append(self.t[j + 1].value)
            j += 2
        return self._resolve(parts), j

    def _resolve(self, parts: list[str]) -> str:
        head = parts[0]
        if head in self.aliases:
            return ".".join([self.aliases[head], *parts[1:]])
        return ".".join(parts)

    def _assign(self, k: int) -> None:
        end = self.rhs_end.get(k, self.n)
        lo = k + 1
        if lo >= end:
            return
        targets = self._targets(k)
        if not targets:
            return
        h = self._head(lo, end)
        destructuring = targets[0][1] is not None or len(targets) > 1

        module = self._required_module(h, end)
        if module is not None:
            for local, key in targets:
                self.aliases[local] = module if key is None or not destructuring else f"{module}.{key}"
            return

        single = None if destructuring else targets[0][0]
        if single is not None:
            self._bind_value(single, h, lo, end)

        call = self._chain(h, end)
        if call is not None and self.punct(call[1], "("):
            dotted = call[0]
            close = self.close_of(call[1])
            if dotted in _NET_CALLS and close >= end - 1:
                for local, _ in targets:
                    self.taint.clear(local)  # a response is not the secret that authenticated it
                if single is not None and dotted in _CHANNELS:
                    self.channels[single] = dotted
                return

        if destructuring and self._whole_env(h, end):
            # const { PORT, API_KEY } = process.env: only the secret-shaped names are secrets.
            source = self.t[h].value
            for local, key in targets:
                name = key or local
                if is_secret_name(name):
                    self.taint.add(local, Origin(f"{source}.env.{name}", self.t[h].line, local), k)
                else:
                    self.taint.clear(local)
            return
        if destructuring and self.ident(h, "process") and h + 1 == end:
            # const { env } = process
            for local, key in targets:
                if (key or local) == "env":
                    self.taint.add(local, Origin("process.env", self.t[h].line, local,
                                                 whole_env=True), k)
            return

        origin = self.first_taint(lo, end)
        if origin is None:
            for local, _ in targets:
                self.taint.clear(local)
            return
        whole = origin.whole_env and self._whole_env(h, end)
        auth_only = self._auth_only(lo, end)
        declared = self.ident(k - 2) and self.t[k - 2].value in _DECLARATION
        for local, _ in targets:
            names = [local]
            if single is not None and not declared and "." not in local:
                names.append(f"this.{local}")  # a class field, read back as this.name
            for name in names:
                self.taint.add(name, Origin(origin.source, origin.line, local,
                                            auth_only=auth_only, whole_env=whole), k)

    def _whole_env(self, h: int, end: int) -> bool:
        """The right-hand side is exactly ``process.env`` (or an alias of it)."""
        if self.ident(h) and self.t[h].value in ("process", "Bun", "Deno") \
                and self.punct(h + 1, ".") and self.ident(h + 2, "env") and h + 3 == end:
            return True
        if self.ident(h) and h + 1 == end:
            origin = self.taint.tainted.get(self.t[h].value)
            return origin is not None and origin.whole_env
        return False

    def _bind_value(self, name: str, h: int, lo: int, end: int) -> None:
        """Track what a plain ``name = …`` binds, beyond taint."""
        self.assigned.add(name)
        literal = self._literal_value(lo, end)
        if literal is not None:
            self.literals[name] = literal
        else:
            self.literals.pop(name, None)
        if self.fixed_destination(lo, end):
            self.fixed.add(name)
        else:
            self.fixed.discard(name)
        credential = self.next_credential[lo]
        if credential < end:
            self.credential_names[name] = (self.credential_at[credential], self.t[credential].line)
        else:
            self.credential_names.pop(name, None)
        chain = self._chain(h, end)
        if chain is None:
            return
        dotted, after = chain
        if after == end and dotted != name and self._interesting(dotted):
            self.aliases[name] = dotted  # const run = cp.exec
        elif self.punct(after, "(") and self.close_of(after) == end - 1:
            if dotted in _PASS_THROUGH:
                inner = self._chain(after + 1, end - 1)
                if inner is not None and self._interesting(inner[0]):
                    self.aliases[name] = inner[0]  # const run = promisify(exec)
            elif dotted == "axios.create":
                self.aliases[name] = "axios"

    @staticmethod
    def _interesting(dotted: str) -> bool:
        return dotted in _SHELL_CALLS or dotted in _PROC_CALLS or dotted in _NET_CALLS \
            or dotted in _FS_READ or dotted in _VM_EVAL

    def _auth_only(self, lo: int, end: int) -> bool:
        """A secret in this object literal sits only under authentication keys."""
        h = self._head(lo, end)
        if not self.punct(h, "{") or self.close_of(h) != end - 1:
            return False
        if end - lo > _WINDOW or not self.spend(end - lo):
            return False
        auth, payload = self._spans(lo, end)
        found = False
        for i in range(lo, end):
            origin = self.taint_at(i)
            if origin is None:
                continue
            found = True
            if _inside(payload, i):
                return False
            if not (_inside(auth, i) or origin.auth_only):
                return False
        return found

    def _for_of(self, i: int) -> None:
        """``for (const [k, v] of EXPR)`` binds ``k`` and ``v`` from ``EXPR``."""
        t = self.t
        declaration = i - 1
        prev = self.tok(declaration)
        if prev is None:
            return
        if prev.kind == "punct" and prev.value in ("]", "}"):
            opener = self.pair[declaration]
            if opener < 1:
                return
            if not self.ident(opener - 1) or t[opener - 1].value not in _DECLARATION:
                return
            targets = self._pattern(opener, declaration)
            head = opener - 1
        elif prev.kind == "ident" and self.ident(i - 2) and t[i - 2].value in _DECLARATION:
            targets = [(prev.value, None)]
            head = i - 2
        else:
            return
        if not (self.punct(head - 1, "(") and self.ident(head - 2, "for")):
            return
        end = self.close_of(head - 1)
        origin = self.first_taint(i + 1, end)
        for local, _ in targets:
            if origin is None:
                self.taint.clear(local)
            else:
                self.taint.add(local, Origin(origin.source, origin.line, local), i)

    # -- literal values and destinations -------------------------------------------

    def _literal_value(self, lo: int, hi: int) -> str | None:
        """The string value of a fully literal expression, or None."""
        if lo >= hi or hi - lo > 64:
            return None
        parts: list[str] = []
        j = lo
        expect_operand = True
        while j < hi:
            tok = self.t[j]
            if expect_operand:
                if tok.kind == "string" and not tok.interpolated:
                    parts.append(tok.value)
                    j = tok.span_end if tok.template and tok.span_end > j else j + 1
                elif tok.kind == "string" and tok.template:
                    value = self._template_literal(j)
                    if value is None:
                        return None
                    parts.append(value)
                    j = tok.span_end
                elif tok.kind == "ident" and tok.value in self.literals:
                    parts.append(self.literals[tok.value])
                    j += 1
                else:
                    return None
                expect_operand = False
            elif tok.kind == "punct" and tok.value == "+":
                expect_operand = True
                j += 1
            else:
                return None
        return "".join(parts) if not expect_operand else None

    def _template_literal(self, j: int) -> str | None:
        """A template whose every interpolation is a literal name, as a string."""
        tok = self.t[j]
        segments = tok.segments or [tok.value]
        holes = tok.holes or []
        out = [segments[0]]
        for m, start in enumerate(holes):
            stop = holes[m + 1] if m + 1 < len(holes) else tok.span_end
            if stop - start != 1 or not self.ident(start) or self.t[start].value not in self.literals:
                return None
            out.append(self.literals[self.t[start].value])
            out.append(segments[m + 1])
        return "".join(out)

    def _static_prefix(self, j: int) -> tuple[str, bool]:
        """A template's text up to its first non-literal interpolation.

        Returns the prefix and whether that interpolation is a name already
        known to hold a fixed destination.
        """
        tok = self.t[j]
        segments = tok.segments or [tok.value]
        holes = tok.holes or []
        out = [segments[0]]
        for m, start in enumerate(holes):
            stop = holes[m + 1] if m + 1 < len(holes) else tok.span_end
            name = self.t[start].value if stop - start == 1 and self.ident(start) else None
            if name is not None and name in self.literals:
                out.append(self.literals[name])
                out.append(segments[m + 1])
                continue
            prefix = "".join(out)
            fixed_name = name is not None and (name in self.fixed or self._constant_name(name))
            return prefix, prefix == "" and fixed_name
        return "".join(out), False

    def _constant_name(self, name: str) -> bool:
        """An upper-case name never assigned here: an imported constant, as the Python rule assumes."""
        return name.isupper() and name not in self.assigned

    def fixed_destination(self, lo: int, hi: int, depth: int = 0) -> bool:
        """Whether a request's destination is settled before the program runs.

        Fully literal counts, as in the Python rule. So does a leading literal
        that already fixes the host (``https://api.github.com/repos/${owner}``),
        a name bound to such a value, and a non-secret environment variable:
        the user configures that, and the skill's author cannot redirect it.
        """
        if lo >= hi:
            return False
        tok = self.t[lo]
        if tok.kind == "punct" and tok.value == "{" and self.close_of(lo) == hi - 1:
            return depth < 3 and self._fixed_options(lo, hi, depth + 1)
        if tok.kind == "ident" and tok.value == "new" and self.ident(lo + 1, "URL") \
                and self.punct(lo + 2, "(") and depth < 3:
            # new URL(fixed) or new URL("/path", fixed): the base settles the host.
            close = self.close_of(lo + 2)
            first_end = self._skip_value(lo + 3, close)
            if first_end >= close:
                return self.fixed_destination(lo + 3, close, depth + 1)
            first = self.tok(lo + 3)
            relative = first is not None and first.kind == "string" and "://" not in first.value
            return relative and self.fixed_destination(first_end + 1, close, depth + 1)
        if self._literal_value(lo, hi) is not None:
            return True
        if tok.kind == "string":
            if tok.template and tok.interpolated:
                prefix, fixed_name = self._static_prefix(lo)
                return fixed_name or bool(_FIXED_HOST.match(prefix))
            return bool(_FIXED_HOST.match(tok.value))
        if tok.kind == "ident":
            if tok.value in ("process", "Bun", "Deno") and self.punct(lo + 1, ".") \
                    and self.ident(lo + 2, "env") and lo not in self.static:
                return True  # a configured, non-secret variable
            return tok.value in self.fixed or self._constant_name(tok.value)
        return False

    def _fixed_options(self, lo: int, hi: int, depth: int) -> bool:
        j = lo + 1
        while j < hi - 1:
            tok = self.t[j]
            if tok.kind in ("ident", "string") and self._is_key(j) \
                    and tok.value.lower() in _DESTINATION_KEYS:
                vlo = j + 2
                return self.fixed_destination(vlo, self._skip_value(vlo, hi - 1), depth)
            if tok.kind == "punct" and tok.value in _OPEN:
                j = self.close_of(j) + 1
                continue
            j += 1
        return False

    # -- calls ----------------------------------------------------------------------

    def _callee(self, c: int) -> tuple[str, int] | None:
        """Resolve the call whose ``(`` is at ``c``: (dotted callee, first token index)."""
        t = self.t
        parts: list[str] = []
        j = c - 1
        dangling = False
        while j >= 0 and len(parts) < _MAX_CHAIN:
            tok = t[j]
            if tok.kind != "ident":
                break
            parts.append(tok.value)
            if self.punct(j - 1, "."):
                j -= 2
                dangling = True
                continue
            dangling = False
            j -= 1
            break
        if not parts:
            return None
        parts.reverse()
        if dangling:
            # require("child_process").exec(…)
            if self.punct(j, ")"):
                opener = self.pair[j]
                s = self.tok(opener + 1)
                if opener > 0 and self.ident(opener - 1, "require") and s is not None \
                        and s.kind == "string" and opener + 2 == j:
                    module = self.add_module(s.value, s.line)
                    return ".".join([module, *parts]), opener - 1
            return None
        first = j + 1
        if self.ident(first - 1, "function"):
            return None  # a declaration, not a call
        if self.punct(self.close_of(c) + 1, "{") and (
            first == 0 or self.punct(first - 1, "{") or self.punct(first - 1, "}")
            or self.punct(first - 1, ";") or self.punct(first - 1, ",")
            or (self.ident(first - 1) and t[first - 1].value in ("async", "static", "get", "set"))
        ):
            return None  # a method definition
        return self._resolve(parts), first

    def _call(self, c: int) -> None:
        callee = self._callee(c)
        if callee is None:
            return
        dotted, _first = callee
        if dotted in ("require", "import"):
            s = self.tok(c + 1)
            if s is not None and s.kind == "string":
                self.add_module(s.value, s.line)
            return
        close = self.close_of(c)
        line = self.t[c].line
        lo = c + 1

        if dotted in _SHELL_CALLS:
            self._shell(dotted, line, lo, close)
        elif dotted in _PROC_CALLS:
            if self._spawns_shell(lo, close):
                self._shell(dotted, line, lo, close)
            else:
                self.observe(Capability.PROC_EXEC, line, f"{dotted}(…)", f"runs a program via {dotted}")
        elif dotted in _EVAL_CALLS:
            if not self._literal_arguments(lo, close, first_only=True):
                self._eval("eval", line)
        elif dotted in _FUNCTION_CTORS:
            if not self._literal_arguments(lo, close, first_only=False):
                self._eval("new Function", line)
        elif dotted in _VM_EVAL:
            if not self._literal_arguments(lo, close, first_only=True):
                self._eval(dotted, line)
        elif dotted in _TIMERS:
            first_end = self._skip_value(lo, close)
            head = self.tok(lo)
            if head is not None and head.kind == "string" and self._literal_value(lo, first_end) is None:
                self._eval(f"{dotted} given a string", line)

        if dotted in _FS_READ:
            self.observe(Capability.FS_READ, line, f"{dotted}(…)", f"reads files via {dotted}")
            self._credential_read(lo, close, line)
        elif dotted in _FS_WRITE:
            self.observe(Capability.FS_WRITE, line, f"{dotted}(…)", f"writes files via {dotted}")

        if dotted in _NET_CALLS:
            for capability in self._direction(dotted, lo, close):
                self.observe(capability, line, f"{dotted}(…)", f"network call via {dotted}")
            if len(self.result.taint_flows) < MAX_FLOWS:
                origin = self.first_taint(lo, close)
                if origin is not None:
                    self._flow(origin, dotted, line, self._auth_shape(dotted, lo, close))
            return

        parts = dotted.split(".")
        if len(parts) == 2 and parts[1] in _CHANNEL_SENDS and parts[0] in self.channels:
            if len(self.result.taint_flows) < MAX_FLOWS:
                origin = self.first_taint(lo, close)
                if origin is not None:
                    self._flow(origin, f"{self.channels[parts[0]]} → {dotted}", line, False)
            return
        if len(parts) == 2 and parts[1] in _CONTAINER_WRITES and parts[0] != "Object":
            origin = self.first_taint(lo, close)
            if origin is not None:
                self.taint.add(parts[0], Origin(origin.source, origin.line, parts[0]), c)
        elif dotted == "Object.assign" and self.ident(lo) and self.punct(lo + 1, ","):
            origin = self.first_taint(lo + 2, close)
            if origin is not None:
                self.taint.add(self.t[lo].value, Origin(origin.source, origin.line, self.t[lo].value), c)

    def _tagged_template(self, i: int) -> None:
        """``$`cmd``: zx, execa and Bun run a tagged template as a shell command."""
        prev = self.t[i - 1]
        if prev.kind != "ident":
            return
        if self.punct(i - 2, "."):
            if not self.ident(i - 3):
                return
            name = self._resolve([self.t[i - 3].value, prev.value])
        else:
            name = self._resolve([prev.value])
            if prev.value == "$" and self.zx:
                name = "zx.$"
        if name not in _SHELL_TAGS:
            return
        line = self.t[i].line
        self.result.shell_exec.append((f"{name} tagged template", line))
        self.observe(Capability.SHELL_EXEC, line, f"{prev.value}`…`", f"runs a shell via {name}")
        self._shell_flow(name, line, i, max(i + 1, self.t[i].span_end))

    def _shell(self, dotted: str, line: int, lo: int, close: int) -> None:
        self.result.shell_exec.append((dotted, line))
        self.observe(Capability.SHELL_EXEC, line, f"{dotted}(…)", f"runs a shell via {dotted}")
        self._shell_flow(dotted, line, lo, close)

    def _shell_flow(self, dotted: str, line: int, lo: int, hi: int) -> None:
        """A secret interpolated into a shelled-out network command (``curl -d …``)."""
        if len(self.result.taint_flows) >= MAX_FLOWS:
            return
        origin = self.first_taint(lo, hi)
        if origin is None or hi - lo > _WINDOW or not self.spend(hi - lo):
            return
        command = next(
            (m.group(0) for i in range(lo, hi)
             if self.t[i].kind == "string" and (m := _NET_COMMAND.search(self.t[i].value))),
            None,
        )
        if command is None:
            return
        self._flow(origin, f"{dotted} running {command}", line, self._shell_auth(lo, hi))

    def _shell_auth(self, lo: int, close: int) -> bool:
        """Every secret in a shelled-out command is a request header (``-H "…: Bearer …"``)."""
        found = False
        for i in range(lo, close):
            if self.taint_at(i) is None:
                continue
            found = True
            before = self._text_before(i, lo)
            if before is None or not _HEADER_CONTEXT.search(before):
                return False
        return found

    def _text_before(self, i: int, lo: int) -> str | None:
        """The literal command text written immediately before token ``i``."""
        for j in range(i - 1, max(lo - 1, i - 64), -1):
            tok = self.t[j]
            if tok.kind == "string" and tok.template and tok.holes and tok.span_end > i:
                for m, start in enumerate(tok.holes):
                    stop = tok.holes[m + 1] if m + 1 < len(tok.holes) else tok.span_end
                    if start <= i < stop:
                        assert tok.segments is not None
                        return tok.segments[m]
                return None
            if tok.kind == "string" and self.punct(j + 1, "+") and j + 2 == i:
                return tok.value
        return None

    def _spawns_shell(self, lo: int, close: int) -> bool:
        if close - lo > _WINDOW or not self.spend(close - lo):
            return False
        program = self.tok(lo)
        if program is not None and program.kind == "string" and program.value in _SHELL_PROGRAMS \
                and any(self.t[i].kind == "string" and self.t[i].value in _SHELL_FLAGS
                        for i in range(lo + 1, close)):
            return True
        for i in range(lo, close):
            if self.ident(i, "shell") and self.punct(i + 1, ":"):
                value = self.tok(i + 2)
                if value is not None and ((value.kind == "ident" and value.value == "true")
                                          or (value.kind == "string" and value.value)):
                    return True
        return False

    def _literal_arguments(self, lo: int, close: int, *, first_only: bool) -> bool:
        j = lo
        while j < close:
            end = self._skip_value(j, close)
            if self._literal_value(j, end) is None:
                return False
            if first_only:
                return True
            j = end + 1
        return True

    def _eval(self, name: str, line: int) -> None:
        self.result.dynamic_eval.append((name, line))
        self.observe(Capability.CODE_EVAL, line, f"{name}(…)", f"evaluates code via {name}")

    def _credential_read(self, lo: int, close: int, line: int) -> None:
        if close - lo > _WINDOW or not self.spend(close - lo):
            return
        for i in range(lo, close):
            tok = self.t[i]
            value: str | None = None
            if i in self.credential_at:
                value = self.credential_at[i]
            elif tok.kind == "ident" and tok.value in self.credential_names and not self.punct(i - 1, "."):
                value = self.credential_names[tok.value][0]
            if value is not None:
                self.result.credential_paths.append((value, line))
                self.observe(Capability.SECRET_ACCESS, line, value, "reads a credential file")
                return

    def _direction(self, dotted: str, lo: int, close: int) -> tuple[Capability, ...]:
        caps = _NET_CALLS[dotted]
        if dotted not in _FETCH_LIKE or close - lo > _WINDOW or not self.spend(close - lo):
            return caps
        for i in range(lo, close):
            tok = self.t[i]
            if tok.kind != "ident" or not self._is_key(i):
                continue
            if tok.value == "body":
                return (Capability.NET_OUTBOUND,)
            value = self.tok(i + 2)
            if tok.value == "method" and value is not None and value.kind == "string" \
                    and value.value.upper() in _SENDING_METHODS:
                return (Capability.NET_OUTBOUND,)
        return caps

    def _flow(self, origin: Origin, sink: str, line: int, authentication: bool) -> None:
        self.result.taint_flows.append(
            TaintFlow(
                source=origin.source,
                sink=sink,
                variable=origin.variable,
                source_line=origin.line,
                sink_line=line,
                is_authentication=authentication,
            )
        )

    # -- authentication shape -----------------------------------------------------------

    def _spans(self, lo: int, hi: int) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
        """Token ranges under authentication keys, and under body keys."""
        auth: list[tuple[int, int]] = []
        payload: list[tuple[int, int]] = []
        for i in range(lo, hi):
            tok = self.t[i]
            if tok.kind not in ("ident", "string"):
                continue
            key = tok.value.lower()
            if self._is_key(i):
                if key in _AUTH_KEYS:
                    auth.append((i + 2, self._skip_value(i + 2, hi)))
                elif key in _PAYLOAD_KEYS:
                    payload.append((i + 2, self._skip_value(i + 2, hi)))
            elif tok.kind == "ident" and key == "headers" and (
                self.punct(i - 1, "{") or self.punct(i - 1, ",")
            ) and (self.punct(i + 1, ",") or self.punct(i + 1, "}")):
                auth.append((i, i + 1))  # shorthand { headers }
        return auth, payload

    def _auth_shape(self, dotted: str, lo: int, close: int) -> bool:
        """True when every secret is authentication and the destination is fixed.

        Mirrors the Python rule: a credential in a header sent to a fixed
        endpoint is authentication; one in a body, a query string, or sent to
        a destination computed at runtime is not.
        """
        first_end = self._skip_value(lo, close)
        if not self.fixed_destination(lo, first_end):
            return False
        if close - lo > _WINDOW or not self.spend(2 * (close - lo)):
            return False
        auth, payload = self._spans(lo, close)
        if dotted in _POSITIONAL_BODY and self.punct(first_end, ","):
            payload.append((first_end + 1, self._skip_value(first_end + 1, close)))
        found = False
        for i in range(lo, close):
            origin = self.taint_at(i)
            if origin is None:
                continue
            found = True
            if _inside(payload, i):
                return False
            if not (_inside(auth, i) or origin.auth_only):
                return False
        return found


def analyze_javascript(text: str, path: str) -> JsAnalysis:
    """Tokenise and read one JavaScript or TypeScript file."""
    first_line = text.split("\n", 1)[0] if text.startswith("#!") else ""
    tokens = tokenize(text)
    reader = _Reader(path, tokens, zx="zx" in first_line)
    result = reader.run()
    if len(text) > MAX_JS_CHARS and not result.truncated:
        result.truncated = f"only the first {MAX_JS_CHARS} characters were analysed"
    return result
