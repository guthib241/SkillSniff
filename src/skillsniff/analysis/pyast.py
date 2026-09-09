"""Python AST analysis.

Regex over source code cannot tell ``subprocess.run(cmd, shell=True)`` from the
string ``"shell=True"`` in a docstring warning against it, and it cannot follow a
value from ``os.environ`` into an HTTP request body. Both distinctions matter, so
bundled Python is parsed properly.

Two passes run over the tree:

1. **Capability extraction** — imports and call targets are mapped onto the
   capability taxonomy, with the call site kept as evidence.
2. **Taint-lite dataflow** — values originating at a *secret source* (environment
   access, credential file reads, keyring lookups) are tracked through
   assignments, f-strings, containers, and concatenation, and a finding is raised
   when one reaches a *network sink*. This is intraprocedural and deliberately
   conservative: it follows local names and simple containers, not arbitrary
   aliasing, so it under-reports rather than guesses.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from skillsniff.model.capability import Capability, Observation, Source
from skillsniff.model.finding import Confidence, Evidence

# ---------------------------------------------------------------------------
# Capability tables
# ---------------------------------------------------------------------------

#: Imported module (top-level) -> capabilities it grants.
IMPORT_CAPABILITIES: dict[str, tuple[Capability, ...]] = {
    "subprocess": (Capability.PROC_EXEC,),
    "os": (),  # too broad to attribute on import alone; attributed per-call
    "shutil": (Capability.FS_WRITE,),
    "pathlib": (),
    # Importing a network library says the network is *reachable*, not which
    # direction is used. Attributing both fetch and send on an import made a
    # send-only script satisfy the "untrusted input" leg of the lethal-trifecta
    # check, which is a false positive. Direction is decided at the call site
    # by CALL_CAPABILITIES below; imports contribute nothing directional.
    "socket": (Capability.NET_DNS,),
    "ssl": (),
    "http": (),
    "urllib": (),
    "requests": (),
    "httpx": (),
    "aiohttp": (),
    "urllib3": (),
    "ftplib": (),
    "smtplib": (),
    "paramiko": (Capability.SECRET_ACCESS,),
    "telnetlib": (),
    "boto3": (Capability.CREDENTIAL_HANDLING,),
    "keyring": (Capability.SECRET_ACCESS,),
    "pip": (Capability.PKG_INSTALL,),
    "pty": (Capability.SHELL_EXEC,),
    "ctypes": (Capability.CODE_EVAL,),
    "pickle": (Capability.CODE_EVAL,),
    "marshal": (Capability.CODE_EVAL,),
    "importlib": (Capability.CODE_EVAL,),
    "git": (Capability.GIT_WRITE,),
    "dns": (Capability.NET_DNS,),
}

#: Dotted call target -> capabilities. Matched on the longest suffix, so both
#: ``subprocess.run`` and ``sp.run`` (aliased import) resolve.
CALL_CAPABILITIES: dict[str, tuple[Capability, ...]] = {
    "subprocess.run": (Capability.PROC_EXEC,),
    "subprocess.call": (Capability.PROC_EXEC,),
    "subprocess.check_call": (Capability.PROC_EXEC,),
    "subprocess.check_output": (Capability.PROC_EXEC,),
    "subprocess.Popen": (Capability.PROC_EXEC,),
    "subprocess.getoutput": (Capability.SHELL_EXEC,),
    "subprocess.getstatusoutput": (Capability.SHELL_EXEC,),
    "os.system": (Capability.SHELL_EXEC,),
    "os.popen": (Capability.SHELL_EXEC,),
    "os.execv": (Capability.PROC_EXEC,),
    "os.execve": (Capability.PROC_EXEC,),
    "os.execvp": (Capability.PROC_EXEC,),
    "os.spawnl": (Capability.PROC_EXEC,),
    "os.spawnv": (Capability.PROC_EXEC,),
    "os.fork": (Capability.PROC_EXEC,),
    "os.posix_spawn": (Capability.PROC_EXEC,),
    "pty.spawn": (Capability.SHELL_EXEC,),
    "os.remove": (Capability.FS_DELETE,),
    "os.unlink": (Capability.FS_DELETE,),
    "os.rmdir": (Capability.FS_DELETE,),
    "os.removedirs": (Capability.FS_DELETE,),
    "shutil.rmtree": (Capability.FS_DELETE,),
    "shutil.copy": (Capability.FS_WRITE,),
    "shutil.copytree": (Capability.FS_WRITE,),
    "shutil.move": (Capability.FS_WRITE,),
    "os.makedirs": (Capability.FS_WRITE,),
    "os.mkdir": (Capability.FS_WRITE,),
    "os.chmod": (Capability.FS_WRITE,),
    "os.rename": (Capability.FS_WRITE,),
    "os.getenv": (Capability.ENV_READ,),
    "os.environ.get": (Capability.ENV_READ,),
    "os.putenv": (Capability.ENV_WRITE,),
    "os.setenv": (Capability.ENV_WRITE,),
    "eval": (Capability.CODE_EVAL,),
    "exec": (Capability.CODE_EVAL,),
    "compile": (Capability.CODE_EVAL,),
    "__import__": (Capability.CODE_EVAL,),
    "importlib.import_module": (Capability.CODE_EVAL,),
    "pickle.loads": (Capability.CODE_EVAL,),
    "pickle.load": (Capability.CODE_EVAL,),
    "marshal.loads": (Capability.CODE_EVAL,),
    "requests.get": (Capability.NET_FETCH,),
    "requests.post": (Capability.NET_OUTBOUND,),
    "requests.put": (Capability.NET_OUTBOUND,),
    "requests.patch": (Capability.NET_OUTBOUND,),
    "requests.delete": (Capability.NET_OUTBOUND,),
    "requests.request": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "requests.Session": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "httpx.get": (Capability.NET_FETCH,),
    "httpx.post": (Capability.NET_OUTBOUND,),
    "httpx.Client": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "urllib.request.urlopen": (Capability.NET_FETCH,),
    "urlopen": (Capability.NET_FETCH,),
    "urllib.request.urlretrieve": (Capability.NET_FETCH,),
    "socket.socket": (Capability.NET_OUTBOUND,),
    "socket.create_connection": (Capability.NET_OUTBOUND,),
    "socket.gethostbyname": (Capability.NET_DNS,),
    "smtplib.SMTP": (Capability.NET_OUTBOUND,),
    "ftplib.FTP": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "socket.recv": (Capability.NET_FETCH,),
    "socket.send": (Capability.NET_OUTBOUND,),
    "socket.sendall": (Capability.NET_OUTBOUND,),
    "aiohttp.ClientSession": (Capability.NET_FETCH, Capability.NET_OUTBOUND),
    "httpx.AsyncClient": (Capability.NET_FETCH, Capability.NET_OUTBOUND),
    "paramiko.SSHClient": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "boto3.client": (Capability.NET_OUTBOUND, Capability.NET_FETCH),
    "keyring.get_password": (Capability.SECRET_ACCESS,),
    "open": (Capability.FS_READ,),
    "Path.write_text": (Capability.FS_WRITE,),
    "Path.write_bytes": (Capability.FS_WRITE,),
    "Path.read_text": (Capability.FS_READ,),
    "Path.read_bytes": (Capability.FS_READ,),
    "Path.unlink": (Capability.FS_DELETE,),
}

#: Names that read secrets. Reaching a network sink from one of these is the
#: canonical exfiltration shape.
SECRET_SOURCES = frozenset(
    {
        "os.environ",
        "os.getenv",
        "os.environ.get",
        "keyring.get_password",
        "getpass.getpass",
        "boto3.Session",
    }
)

NETWORK_SINKS = frozenset(
    {
        "requests.get", "requests.post", "requests.put", "requests.patch",
        "requests.delete", "requests.request", "httpx.get", "httpx.post",
        "httpx.put", "httpx.request", "urlopen", "urllib.request.urlopen",
        "urllib.request.Request", "socket.send", "socket.sendall",
        "smtplib.SMTP.sendmail", "session.post", "session.get", "client.post",
        "sock.send", "sock.sendall", "conn.send", "s.send", "s.sendall",
    }
)

#: Environment variable names that indicate a credential rather than config.
SECRET_NAME_RE = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|API[_-]?KEY|APIKEY|CREDENTIAL|PRIVATE[_-]?KEY"
    r"|ACCESS[_-]?KEY|AUTH|SESSION[_-]?KEY|CLIENT[_-]?SECRET",
    re.IGNORECASE,
)

#: Filenames whose presence in a path literal implies credential access.
CREDENTIAL_PATH_MARKERS = (
    ".ssh", ".aws", ".gnupg", ".kube", ".docker/config", "id_rsa", "id_ed25519",
    ".netrc", ".npmrc", ".pypirc", "credentials", "secrets", ".env",
    "keychain", "cookies.sqlite", "login data",
)


@dataclass
class TaintFlow:
    """A secret value observed reaching a network sink."""

    source: str
    sink: str
    variable: str
    source_line: int
    sink_line: int
    #: True when the credential reaches the sink through an authentication
    #: header and the destination is a literal, not a computed or fetched, URL.
    #: That is a normal API client, not exfiltration.
    is_authentication: bool = False


@dataclass
class PyAnalysis:
    """Everything the AST pass learned about one Python file."""

    path: str
    syntax_ok: bool = True
    syntax_error: str = ""
    observations: list[Observation] = field(default_factory=list)
    imports: set[str] = field(default_factory=set)
    calls: list[tuple[str, int]] = field(default_factory=list)
    string_literals: list[tuple[str, int]] = field(default_factory=list)
    shell_true_lines: list[int] = field(default_factory=list)
    dynamic_eval_lines: list[tuple[str, int]] = field(default_factory=list)
    taint_flows: list[TaintFlow] = field(default_factory=list)
    credential_paths: list[tuple[str, int]] = field(default_factory=list)


def _dotted(node: ast.AST) -> str:
    """Render an attribute/name chain as a dotted string, or '' if it is not one."""
    parts: list[str] = []
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    elif isinstance(current, ast.Call):
        inner = _dotted(current.func)
        if inner:
            parts.append(inner)
    else:
        return ""
    return ".".join(reversed(parts))


def _resolve(dotted: str, aliases: dict[str, str]) -> str:
    """Resolve an aliased import back to its canonical dotted path."""
    if not dotted:
        return ""
    head, _, tail = dotted.partition(".")
    canonical = aliases.get(head, head)
    return f"{canonical}.{tail}" if tail else canonical


def _match_capability(dotted: str) -> tuple[Capability, ...]:
    if dotted in CALL_CAPABILITIES:
        return CALL_CAPABILITIES[dotted]
    # Fall back to the last two segments, so `self.session.post` matches
    # `session.post` and an aliased `sp.run` matches `subprocess.run` once
    # resolved.
    segments = dotted.split(".")
    for width in (2, 1):
        if len(segments) >= width:
            suffix = ".".join(segments[-width:])
            if suffix in CALL_CAPABILITIES:
                return CALL_CAPABILITIES[suffix]
    return ()


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str, result: PyAnalysis) -> None:
        self.path = path
        self.result = result
        self.aliases: dict[str, str] = {}
        #: local variable name -> (secret source, line) for taint tracking
        self.tainted: dict[str, tuple[str, int]] = {}

    # -- imports ------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            self.result.imports.add(alias.name)
            self.aliases[alias.asname or top] = alias.name
            self._add_import_capabilities(top, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        top = module.split(".")[0]
        if module:
            self.result.imports.add(module)
            self._add_import_capabilities(top, node.lineno)
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def _add_import_capabilities(self, top: str, line: int) -> None:
        for capability in IMPORT_CAPABILITIES.get(top, ()):
            self.result.observations.append(
                Observation(
                    capability=capability,
                    source=Source.CODE,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(path=self.path, line=line, excerpt=f"import {top}"),
                    detail=f"imports {top}",
                )
            )

    # -- calls --------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        raw = _dotted(node.func)
        dotted = _resolve(raw, self.aliases)
        if dotted:
            self.result.calls.append((dotted, node.lineno))

        if dotted in ("os.getenv", "os.environ.get") and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if SECRET_NAME_RE.search(first.value):
                    self.result.observations.append(
                        Observation(
                            capability=Capability.CREDENTIAL_HANDLING,
                            source=Source.CODE,
                            confidence=Confidence.HIGH,
                            evidence=Evidence(
                                path=self.path,
                                line=node.lineno,
                                excerpt=f"{dotted}({first.value!r})",
                            ),
                            detail=f"{first.value} is a credential-shaped variable name",
                        )
                    )

        for capability in _match_capability(dotted):
            self.result.observations.append(
                Observation(
                    capability=capability,
                    source=Source.CODE,
                    confidence=Confidence.HIGH,
                    evidence=Evidence(
                        path=self.path, line=node.lineno, excerpt=f"{dotted}(...)"
                    ),
                    detail=f"calls {dotted}",
                )
            )

        # shell=True escalates a subprocess call to full shell execution.
        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                self.result.shell_true_lines.append(node.lineno)
                self.result.observations.append(
                    Observation(
                        capability=Capability.SHELL_EXEC,
                        source=Source.CODE,
                        confidence=Confidence.HIGH,
                        evidence=Evidence(
                            path=self.path, line=node.lineno, excerpt=f"{dotted}(..., shell=True)"
                        ),
                        detail="subprocess invoked with shell=True",
                    )
                )

        # eval/exec on anything other than a literal is dynamic code execution.
        base = dotted.split(".")[-1]
        if base in ("eval", "exec", "compile") and node.args:
            if not isinstance(node.args[0], ast.Constant):
                self.result.dynamic_eval_lines.append((base, node.lineno))

        # pip install via subprocess
        if dotted.startswith(("subprocess.", "os.system", "os.popen")):
            joined = " ".join(
                arg.value
                for arg in ast.walk(node)
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            )
            lowered = joined.lower()
            if "pip install" in lowered or "npm install" in lowered or "pip3 install" in lowered:
                self.result.observations.append(
                    Observation(
                        capability=Capability.PKG_INSTALL,
                        source=Source.CODE,
                        confidence=Confidence.HIGH,
                        evidence=Evidence(
                            path=self.path, line=node.lineno, excerpt=joined[:100]
                        ),
                        detail="installs packages via a subprocess",
                    )
                )

        self._check_taint_sink(dotted, node)
        self.generic_visit(node)

    # -- subscripts ---------------------------------------------------------

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Attribute os.environ['X'] as an environment read.

        Subscript access is the most common way to read an environment variable
        and it is not a Call, so the call table alone misses it entirely.
        """
        base = _resolve(_dotted(node.value), self.aliases)
        if base in ("os.environ", "process.env"):
            key = ""
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                key = node.slice.value
            self.result.observations.append(
                Observation(
                    capability=Capability.ENV_READ,
                    source=Source.CODE,
                    confidence=Confidence.HIGH,
                    evidence=Evidence(
                        path=self.path,
                        line=node.lineno,
                        excerpt=f"{base}[{key!r}]" if key else f"{base}[...]",
                    ),
                    detail=f"reads environment variable {key!r}" if key else "reads the environment",
                )
            )
            if key and SECRET_NAME_RE.search(key):
                self.result.observations.append(
                    Observation(
                        capability=Capability.CREDENTIAL_HANDLING,
                        source=Source.CODE,
                        confidence=Confidence.HIGH,
                        evidence=Evidence(
                            path=self.path, line=node.lineno, excerpt=f"{base}[{key!r}]"
                        ),
                        detail=f"{key} is a credential-shaped variable name",
                    )
                )
        self.generic_visit(node)

    # -- assignment / taint -------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        origin = self._taint_origin(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if origin:
                    self.tainted[target.id] = origin
                else:
                    self.tainted.pop(target.id, None)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            origin = self._taint_origin(node.value)
            if origin:
                self.tainted[node.target.id] = origin
        self.generic_visit(node)

    def _taint_origin(self, node: ast.AST | None) -> tuple[str, int] | None:
        """Return (source_name, line) if ``node`` derives from a secret source."""
        if node is None:
            return None
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                dotted = _resolve(_dotted(child.func), self.aliases)
                if dotted in SECRET_SOURCES or dotted.endswith(".getenv"):
                    return dotted, child.lineno
            if isinstance(child, ast.Subscript):
                base = _resolve(_dotted(child.value), self.aliases)
                if base in SECRET_SOURCES:
                    return base, child.lineno
            if isinstance(child, ast.Attribute | ast.Name):
                dotted = _resolve(_dotted(child), self.aliases)
                if dotted in SECRET_SOURCES:
                    return dotted, getattr(child, "lineno", 0)
            if isinstance(child, ast.Name) and child.id in self.tainted:
                return self.tainted[child.id]
        return None

    def _check_taint_sink(self, dotted: str, node: ast.Call) -> None:
        """Record a flow when a tainted value is passed to a network sink."""
        segments = dotted.split(".")
        suffix2 = ".".join(segments[-2:]) if len(segments) >= 2 else dotted
        is_sink = (
            dotted in NETWORK_SINKS
            or suffix2 in NETWORK_SINKS
            or any(dotted.endswith(f".{s.split('.')[-1]}") for s in ("requests.post", "requests.put"))
            and segments[-1] in ("post", "put", "send", "sendall")
        )
        if not is_sink:
            return

        for child in ast.walk(node):
            origin: tuple[str, int] | None = None
            variable = ""
            if isinstance(child, ast.Name) and child.id in self.tainted:
                origin = self.tainted[child.id]
                variable = child.id
            elif isinstance(child, ast.Subscript):
                base = _resolve(_dotted(child.value), self.aliases)
                if base in SECRET_SOURCES:
                    origin = (base, child.lineno)
                    variable = base
            elif isinstance(child, ast.Call):
                inner = _resolve(_dotted(child.func), self.aliases)
                if inner in SECRET_SOURCES or inner.endswith(".getenv"):
                    origin = (inner, child.lineno)
                    variable = inner
            elif isinstance(child, ast.Attribute):
                inner = _resolve(_dotted(child), self.aliases)
                if inner in SECRET_SOURCES:
                    origin = (inner, child.lineno)
                    variable = inner

            if origin:
                self.result.taint_flows.append(
                    TaintFlow(
                        source=origin[0],
                        sink=dotted,
                        variable=variable,
                        source_line=origin[1],
                        sink_line=node.lineno,
                        is_authentication=self._is_auth_shape(node, child),
                    )
                )
                return

    @staticmethod
    def _is_auth_shape(call: ast.Call, tainted: ast.AST) -> bool:
        """True when the tainted value is an auth header on a literal endpoint.

        Both conditions are required. A token in a header sent to a URL built at
        runtime is not obviously authentication, and a token in a request *body*
        is not authentication at all regardless of the destination.
        """
        auth_keywords = {"headers", "auth", "cookies"}
        in_auth_position = False
        for keyword in call.keywords:
            if keyword.arg not in auth_keywords:
                continue
            for node in ast.walk(keyword.value):
                if node is tainted:
                    in_auth_position = True
                    break
            # An Authorization key is the strongest signal available.
            if isinstance(keyword.value, ast.Dict):
                for key in keyword.value.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        if key.value.lower() in ("authorization", "x-api-key", "api-key"):
                            in_auth_position = in_auth_position or any(
                                node is tainted for node in ast.walk(keyword.value)
                            )
        if not in_auth_position:
            return False

        # The destination must be built only from literals.
        target = call.args[0] if call.args else None
        if target is None:
            target = next((k.value for k in call.keywords if k.arg == "url"), None)
        if target is None:
            return False
        return _is_literal_url(target)

    # -- literals -----------------------------------------------------------

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and node.value:
            self.result.string_literals.append((node.value, node.lineno))
            lowered = node.value.lower()
            if any(marker in lowered for marker in CREDENTIAL_PATH_MARKERS) and (
                "/" in node.value or "\\" in node.value or lowered.startswith(".")
            ):
                self.result.credential_paths.append((node.value, node.lineno))
                self.result.observations.append(
                    Observation(
                        capability=Capability.SECRET_ACCESS,
                        source=Source.CODE,
                        confidence=Confidence.MEDIUM,
                        evidence=Evidence(
                            path=self.path, line=node.lineno, excerpt=node.value[:100]
                        ),
                        detail="references a credential path",
                    )
                )
        self.generic_visit(node)


def analyze_python(source: str, path: str) -> PyAnalysis:
    """Parse and analyse one Python source file.

    A syntax error is recorded, not raised: a skill can legitimately bundle a
    Python 2 script or a template, and the right response is reduced coverage
    for that file rather than an aborted scan.
    """
    result = PyAnalysis(path=path)
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError) as exc:
        result.syntax_ok = False
        result.syntax_error = f"{type(exc).__name__}: {exc}"
        return result

    visitor = _Visitor(path, result)
    try:
        visitor.visit(tree)
    except RecursionError:
        result.syntax_ok = False
        result.syntax_error = "RecursionError: expression nesting too deep"
    return result


def _is_literal_url(node: ast.AST) -> bool:
    """True when ``node`` is a URL assembled entirely from string constants.

    Constant, f-string of constants, and concatenation of constants all count.
    A name, call, or subscript does not: those can carry an attacker-chosen host.
    """
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_literal_url(node.left) and _is_literal_url(node.right)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    if isinstance(node, ast.Name):
        # A module-level constant such as API = "https://api.example.com" is the
        # normal way to write this, so a bare uppercase name is accepted.
        return node.id.isupper()
    return False
