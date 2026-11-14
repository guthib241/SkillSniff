"""The analysis context.

Everything expensive — parsing Python, tokenising shell, decoding payloads,
normalising Unicode, classifying URLs — happens exactly once, here, before any
rule runs. Rules then read precomputed structure rather than re-deriving it,
which is the difference between a scan that is linear in file count and one
that is linear in ``files × rules``.

It also means a rule cannot accidentally analyse a file the budget refused.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from skillsniff.analysis.deps import Dependency, parse_manifest
from skillsniff.analysis.external import ExternalResource, find_urls
from skillsniff.analysis.instructions import (
    InstructionAnalysis,
    infer_from_declared_tools,
    infer_from_description,
    infer_from_instructions,
)
from skillsniff.analysis.jsscan import JS_SUFFIXES, JsAnalysis, analyze_javascript
from skillsniff.analysis.pyast import PyAnalysis, analyze_python
from skillsniff.analysis.shell import ShellAnalysis, parse_shell, shadows_interpreters, shell_blocks
from skillsniff.core.config import Config
from skillsniff.core.fs import FileKind, ScannedFile
from skillsniff.core.limits import Budget, CoverageReason
from skillsniff.core.text import TextView
from skillsniff.model.capability import CapabilitySurface
from skillsniff.model.finding import Evidence
from skillsniff.model.skill import Skill

SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ksh"})
#: Interpreters whose shebang marks an extensionless script as JavaScript.
_JS_INTERPRETERS = ("node", "deno", "bun", "zx", "tsx", "ts-node")


def _is_js_script(text: str) -> bool:
    if not text.startswith("#!"):
        return False
    first = text.split("\n", 1)[0]
    return any(name in first.split("/")[-1].split() for name in _JS_INTERPRETERS) or any(
        f"/{name}" in first for name in _JS_INTERPRETERS
    )


@dataclass
class FileContext:
    """A file together with every derived view of it."""

    scanned: ScannedFile
    view: TextView | None = None
    python: PyAnalysis | None = None
    js: JsAnalysis | None = None
    shell: ShellAnalysis | None = None
    urls: list[ExternalResource] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    #: Memoised (scannable, normalised) projections, filled lazily by the rule
    #: scanner. Held here rather than in a module-level cache because a
    #: module-level one is keyed by display path, which collides between scans
    #: of different skills that share a relative filename.
    _projections: tuple[str, str] | None = field(default=None, repr=False)

    @property
    def path(self) -> str:
        return self.scanned.display

    @property
    def text(self) -> str:
        return self.scanned.text or ""

    def evidence(self, line: int | None = None, excerpt: str = "", **kwargs: object) -> Evidence:
        return Evidence(path=self.path, line=line, excerpt=excerpt, **kwargs)  # type: ignore[arg-type]


@dataclass
class AnalysisContext:
    """Everything a rule needs about one skill."""

    skill: Skill
    config: Config
    budget: Budget
    files: list[FileContext] = field(default_factory=list)
    capabilities: CapabilitySurface = field(default_factory=CapabilitySurface)
    externals: list[ExternalResource] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    instructions: InstructionAnalysis = field(default_factory=InstructionAnalysis)

    # -- convenience accessors ---------------------------------------------

    @property
    def name(self) -> str:
        return self.skill.dir_name

    @property
    def entry(self) -> FileContext | None:
        return next(
            (f for f in self.files if f.scanned.relpath == self.skill.entry_relpath and not f.scanned.container),
            None,
        )

    @property
    def entry_path(self) -> str:
        entry = self.entry
        return entry.path if entry else self.skill.entry_relpath

    def text_files(self) -> Iterator[FileContext]:
        yield from (f for f in self.files if f.scanned.is_text)

    def python_files(self) -> Iterator[FileContext]:
        yield from (f for f in self.files if f.python is not None)

    def shell_files(self) -> Iterator[FileContext]:
        yield from (f for f in self.files if f.shell is not None)

    def js_files(self) -> Iterator[FileContext]:
        yield from (f for f in self.files if f.js is not None)

    def entry_evidence(self, line: int | None = None, excerpt: str = "") -> Evidence:
        return Evidence(path=self.entry_path, line=line, excerpt=excerpt)

    def frontmatter_evidence(self, key: str, excerpt: str = "") -> Evidence:
        return Evidence(
            path=self.entry_path,
            line=self.skill.frontmatter.line_of(key),
            excerpt=excerpt,
        )


def build_context(skill: Skill, config: Config, budget: Budget) -> AnalysisContext:
    """Run every derivation pass over a loaded skill."""
    context = AnalysisContext(skill=skill, config=config, budget=budget)

    for scanned in skill.all_files:
        file_context = FileContext(scanned=scanned)
        context.files.append(file_context)

        try:
            _derive(context, file_context)
        except Exception as exc:  # recorded as a gap, never allowed to end the scan
            # An analyser that raises on one file must not abort the scan: a crash
            # anyone can trigger is a way past the scanner. Whatever views were
            # built before the failure are still read by the rules; what the
            # analyser would have established is recorded as unknown, so the
            # verdict cannot be CLEAR.
            budget.note_gap(
                scanned.display,
                CoverageReason.ANALYSIS_ERROR,
                f"{type(exc).__name__}: {str(exc)[:200]}",
            )

    try:
        _collect_capabilities(context)
    except Exception as exc:  # recorded as a gap, never allowed to end the scan
        budget.note_gap(
            context.entry_path, CoverageReason.ANALYSIS_ERROR, f"capability merge: {type(exc).__name__}: {exc}"[:240]
        )
    return context


def _derive(context: AnalysisContext, file_context: FileContext) -> None:
    """Compute every derived view of one file and add it to ``context``."""
    scanned = file_context.scanned
    config = context.config
    budget = context.budget
    if scanned.text is None:
        return

    view = TextView(
        raw=scanned.text,
        path=scanned.display,
        max_decode_depth=config.limits.max_decode_depth,
    )
    file_context.view = view
    budget.encoded_regions_inspected += len(view.decoded)

    suffix = scanned.suffix
    name = scanned.name

    if suffix in (".py", ".pyi"):
        file_context.python = analyze_python(scanned.text, scanned.display)
        if not file_context.python.syntax_ok:
            budget.note_gap(
                scanned.display,
                CoverageReason.UNPARSEABLE,
                file_context.python.syntax_error,
            )
    elif suffix in JS_SUFFIXES or _is_js_script(scanned.text):
        file_context.js = analyze_javascript(scanned.text, scanned.display)
        if file_context.js.truncated:
            budget.note_gap(
                scanned.display,
                CoverageReason.ANALYSIS_TRUNCATED,
                file_context.js.truncated,
            )
    elif suffix in SHELL_SUFFIXES or scanned.text.startswith("#!"):
        file_context.shell = parse_shell(scanned.text, scanned.display)

    # Fenced shell blocks inside Markdown are executable instructions to the
    # agent even though the file is documentation — *unless* the surrounding
    # prose frames them as examples of what not to do. A skill that
    # documents `curl … | bash` as an attack indicator does not thereby
    # acquire the capability to fetch and execute remote code, and treating
    # it as if it did is what makes security documentation unscannable.
    if suffix in (".md", ".markdown"):
        from skillsniff.rules._scan import documentation_framed

        merged = ShellAnalysis(path=scanned.display)
        trust_names = not shadows_interpreters(scanned.text)
        for code, start_line, _language in shell_blocks(scanned.text):
            offset = _offset_of_line(scanned.text, start_line)
            if documentation_framed(scanned.text, offset):
                continue
            block = parse_shell(code, scanned.display, start_line=start_line, trust_names=trust_names)
            merged.commands.extend(block.commands)
            merged.observations.extend(block.observations)
            merged.fetch_to_interpreter.extend(block.fetch_to_interpreter)
            merged.decode_to_interpreter.extend(block.decode_to_interpreter)
            merged.credential_reads.extend(block.credential_reads)
            merged.network_sends.extend(block.network_sends)
            merged.installers.extend(block.installers)
            merged.destructive.extend(block.destructive)
        # A clone in one block and its build in the next is the usual way a
        # README is written, so the link is followed across the file's blocks.
        from skillsniff.analysis.shell import find_clone_runs

        merged.clone_runs = find_clone_runs(merged.commands)
        if merged.commands:
            file_context.shell = merged

    # A URL inside a shell comment is documentation about a URL, not a
    # reference to one, so it must not become an external-resource edge.
    url_source = scanned.text
    # (A JavaScript file with a shebang is not a shell script: ``#`` is not
    # its comment character, so blanking ``#`` lines would hide real code.)
    if (suffix in SHELL_SUFFIXES or scanned.text.startswith("#!")) and file_context.js is None:
        from skillsniff.rules._scan import _blank_shell_comments

        url_source = _blank_shell_comments(scanned.text)
    # Re-fang before extracting: an agent reads hxxps://host[.]tk as a URL,
    # so the trust graph must too. Re-fanging never touches a newline, so
    # the line numbers recorded against each URL stay exact.
    from skillsniff.core.text import refang

    file_context.urls = find_urls(refang(url_source), scanned.display)
    file_context.dependencies = parse_manifest(name, scanned.text, scanned.display)

    context.externals.extend(file_context.urls)
    context.dependencies.extend(file_context.dependencies)


def _collect_capabilities(context: AnalysisContext) -> None:
    """Merge capability observations from every source into one surface."""
    skill = context.skill
    surface = context.capabilities
    entry_path = context.entry_path

    if skill.description:
        surface.extend(
            infer_from_description(
                skill.description, entry_path, skill.frontmatter.line_of("description")
            )
        )

    if skill.declared_tools:
        surface.extend(
            infer_from_declared_tools(
                skill.declared_tools, entry_path, skill.frontmatter.line_of("allowed-tools")
            )
        )

    if skill.body:
        # Line numbers are relative to the body; shift them to file coordinates.
        offset = skill.frontmatter.body_start_line - 1
        analysis = infer_from_instructions(skill.body, entry_path)
        analysis.observations = [
            o
            for o in analysis.observations
            if o.evidence.line is None
            or not _framed(skill.body, o.evidence.line)
        ]
        for observation in analysis.observations:
            evidence = observation.evidence
            if evidence.line is not None:
                observation.evidence = Evidence(
                    path=evidence.path,
                    line=evidence.line + offset,
                    excerpt=evidence.excerpt,
                    decode_chain=evidence.decode_chain,
                    note=evidence.note,
                )
        context.instructions = analysis
        surface.extend(analysis.observations)

    for file_context in context.files:
        if file_context.python is not None:
            surface.extend(file_context.python.observations)
        if file_context.js is not None:
            surface.extend(file_context.js.observations)
        if file_context.shell is not None:
            surface.extend(file_context.shell.observations)

        # Reference documents bundled with the skill are instructions too: the
        # agent loads them on demand and follows what they say.
        scanned = file_context.scanned
        if (
            scanned.is_text
            and scanned.suffix in (".md", ".markdown")
            and scanned.relpath != skill.entry_relpath
        ):
            nested = infer_from_instructions(scanned.text or "", scanned.display)
            surface.extend(
                o
                for o in nested.observations
                if o.evidence.line is None
                or not _framed(scanned.text or "", o.evidence.line)
            )

    from skillsniff.analysis.external import ResourceKind, TrustLevel
    from skillsniff.model.capability import Capability, Observation, Source
    from skillsniff.model.finding import Confidence

    for resource in context.externals:
        if resource.kind in (ResourceKind.REMOTE_SCRIPT, ResourceKind.RAW_FILE):
            located = resource.evidence
            if located is not None and located.line is not None:
                origin = next(
                    (f for f in context.files if f.path == located.path and f.scanned.is_text),
                    None,
                )
                if origin is not None and _framed(origin.text, located.line):
                    continue
            surface.add(
                Observation(
                    capability=Capability.REMOTE_INSTRUCTIONS,
                    source=Source.EXTERNAL,
                    confidence=Confidence.MEDIUM if resource.is_mutable else Confidence.LOW,
                    evidence=resource.evidence or Evidence(path=entry_path),
                    detail=f"references remote content at {resource.host}",
                )
            )

    for dependency in context.dependencies:
        surface.add(
            Observation(
                capability=Capability.PKG_INSTALL,
                source=Source.DEPENDENCY,
                confidence=Confidence.HIGH,
                evidence=dependency.evidence,
                detail=f"declares dependency {dependency.name}",
            )
        )
        if dependency.trust is TrustLevel.SUSPICIOUS:
            surface.add(
                Observation(
                    capability=Capability.PROC_EXEC,
                    source=Source.DEPENDENCY,
                    confidence=Confidence.MEDIUM,
                    evidence=dependency.evidence,
                    detail=f"{dependency.name} runs code at install time",
                )
            )

    # Binary and executable artifacts are capability *and* a coverage problem.
    for file_context in context.files:
        if file_context.scanned.kind == FileKind.EXECUTABLE:
            surface.add(
                Observation(
                    capability=Capability.PROC_EXEC,
                    source=Source.CODE,
                    confidence=Confidence.MEDIUM,
                    evidence=Evidence(
                        path=file_context.path, excerpt=f"{file_context.scanned.size} bytes"
                    ),
                    detail="bundles a compiled or bytecode artifact",
                )
            )


def _offset_of_line(text: str, line: int) -> int:
    """Character offset of the start of 1-based ``line``."""
    offset = 0
    for _ in range(max(0, line - 1)):
        newline = text.find("\n", offset)
        if newline == -1:
            return offset
        offset = newline + 1
    return offset


def _framed(text: str, line: int) -> bool:
    """True when ``line`` sits under prose framing it as an example."""
    from skillsniff.rules._scan import documentation_framed

    return documentation_framed(text, _offset_of_line(text, line))
