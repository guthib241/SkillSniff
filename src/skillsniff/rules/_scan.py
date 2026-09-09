"""Shared scanning helpers for pattern-based rules.

Every rule that matches a pattern gets three projections of each file for free:
the raw text, the normalised text (invisible characters stripped, homoglyphs
folded), and every decoded region (base64, hex, percent, Unicode tags).
Centralising that here means a rule author cannot forget the normalised view and
accidentally ship a detection that a zero-width space defeats.

Matches carry where they were seen. A hit in a decoded region reports the line
of the *encoded* span in the original file plus the decode chain, so the finding
stays navigable.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from skillsniff.analysis.context import AnalysisContext, FileContext
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity

#: Cap on the input handed to any single regex. Backtracking cost is superlinear
#: in input length for some patterns, so bounding the input bounds the damage a
#: crafted file can do even if a rule's pattern is imperfect.
MAX_SCAN_BYTES = 1_000_000


@dataclass(frozen=True)
class Match:
    """One pattern hit, with provenance."""

    text: str
    line: int
    start: int
    end: int
    file: FileContext
    projection: str  # "raw" | "normalized" | "decoded"
    decode_chain: str = ""

    @property
    def path(self) -> str:
        return self.file.path

    def evidence(self, note: str = "") -> Evidence:
        return Evidence(
            path=self.path,
            line=self.line,
            excerpt=self.excerpt,
            decode_chain=self.decode_chain,
            note=note or self._projection_note(),
        )

    def _projection_note(self) -> str:
        if self.projection == "normalized":
            return "only visible after Unicode normalisation"
        if self.projection == "decoded":
            return f"only visible after decoding ({self.decode_chain})"
        return ""

    @property
    def excerpt(self) -> str:
        snippet = self.text.replace("\n", " ").strip()
        return snippet[:157] + "…" if len(snippet) > 158 else snippet

    @property
    def is_documented(self) -> bool:
        """True when surrounding prose frames this as an example, not an instruction."""
        view = self.file.view
        if view is None or self.projection == "decoded":
            return False
        return documentation_framed(view.raw, self.start, self.end)


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


#: Suffixes whose comments are prose about the code, not the code itself.
_SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ksh", ".fish"})


def _projections(file: FileContext, view) -> tuple[str, str]:
    """Return (scannable_raw, scannable_normalised) for one file, memoised.

    Every rule asks for the same two strings. Recomputing them per rule made
    ``normalize()`` run once per rule over the same megabyte, which dominated
    the profile on a large file — and a large file is exactly the shape an
    attacker would choose. The memo lives on the FileContext so it is scoped to
    one scan; a module-level cache keyed by display path collides between skills
    that share a relative filename.
    """
    if file._projections is not None:
        return file._projections

    from skillsniff.core.text import normalize

    raw = view.raw[:MAX_SCAN_BYTES]
    # For shell scripts, comments are blanked out (offsets preserved so line
    # numbers stay correct). A commented-out `rm -rf $HOME` in a script that
    # warns against it is documentation, and reporting it as a destructive
    # operation is the single noisiest false positive this tool can produce.
    if file.scanned.suffix in _SHELL_SUFFIXES or raw.startswith("#!"):
        raw = _blank_shell_comments(raw)

    result = (raw, normalize(raw)[:MAX_SCAN_BYTES])
    file._projections = result
    return result


def _scannable_text(file: FileContext, view) -> str:
    """The raw projection of a file that pattern rules should see."""
    return _projections(file, view)[0]


def _blank_shell_comments(text: str) -> str:
    out: list[str] = []
    for line in text.split("\n"):
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
        out.append(line[:cut] + " " * (len(line) - cut))
    return "\n".join(out)


def scan_file(
    file: FileContext,
    pattern: re.Pattern[str],
    *,
    include_normalized: bool = True,
    include_decoded: bool = True,
    limit: int = 25,
) -> Iterator[Match]:
    """Yield matches of ``pattern`` across every projection of one file."""
    view = file.view
    if view is None:
        return

    raw, normalized_text = _projections(file, view)
    seen_spans: set[tuple[int, int]] = set()
    count = 0

    for match in pattern.finditer(raw):
        if count >= limit:
            return
        span = (match.start(), match.end())
        seen_spans.add(span)
        count += 1
        yield Match(
            text=match.group(0),
            line=_line_at(raw, match.start()),
            start=match.start(),
            end=match.end(),
            file=file,
            projection="raw",
        )

    if include_normalized:
        # The normalised view is of the *scannable* projection, not the untouched
        # raw text — otherwise blanked shell comments come straight back through
        # this pass.
        normalized = normalized_text
        if normalized != raw:
            for match in pattern.finditer(normalized):
                if count >= limit:
                    return
                # Only report if the raw text did not already yield this span:
                # normalisation shifts offsets, so compare on content instead.
                if any(view.raw[s:e] == match.group(0) for s, e in seen_spans):
                    continue
                count += 1
                yield Match(
                    text=match.group(0),
                    line=_line_at(normalized, match.start()),
                    start=match.start(),
                    end=match.end(),
                    file=file,
                    projection="normalized",
                )

    if include_decoded:
        for region in view.decoded:
            for match in pattern.finditer(region.text[:MAX_SCAN_BYTES]):
                if count >= limit:
                    return
                count += 1
                yield Match(
                    text=match.group(0),
                    line=region.origin_line,
                    start=region.origin_start,
                    end=region.origin_end,
                    file=file,
                    projection="decoded",
                    decode_chain=region.chain,
                )


def scan(
    context: AnalysisContext,
    pattern: re.Pattern[str],
    *,
    suffixes: frozenset[str] | set[str] | None = None,
    include_normalized: bool = True,
    include_decoded: bool = True,
    limit_per_file: int = 25,
) -> Iterator[Match]:
    """Yield matches of ``pattern`` across every text file in the skill."""
    for file in context.text_files():
        if suffixes is not None and file.scanned.suffix not in suffixes:
            continue
        yield from scan_file(
            file,
            pattern,
            include_normalized=include_normalized,
            include_decoded=include_decoded,
            limit=limit_per_file,
        )


# ---------------------------------------------------------------------------
# Documentation framing
# ---------------------------------------------------------------------------

#: Prose that frames the following content as something to recognise or avoid,
#: rather than something to do. A security skill that documents `curl … | bash`
#: as an attack indicator is the archetypal false positive for every rule in
#: this tool, and this is how it is distinguished from an actual instruction.
_FRAMING_SIGNALS = re.compile(
    r"\b(?:never|do\s*n[o']?t|don't|must\s+not|should\s+not|avoid|refuse|reject|"
    r"anti-?pattern|bad\s+(?:example|practice)|wrong|incorrect|unsafe|"
    r"example[s]?\s+of|for\s+example|e\.g\.|such\s+as|illustrat\w+|"
    r"malicious|attacker|attack|exploit|vulnerab\w+|red[- ]team|adversar\w+|"
    r"look\s+for|watch\s+(?:out\s+)?for|indicator|detect\w*|spot\w*|"
    r"warning|caution|danger|threat|suspicious|red\s+flag|smell|"
    r"what\s+not\s+to|instead\s+of|rather\s+than|test\s+string|payload\s+sample|"
    r"confirm\s+it|verify\s+(?:it|the\s+\w+)\s+(?:refus|reject|block)|sample|demonstrat|"
    r"if\s+you\s+see)",
    # No trailing \b: these terms appear inflected ("refuses", "test strings",
    # "detects"), and requiring a boundary made the check miss exactly the
    # documentation phrasing it exists to recognise.
    re.IGNORECASE,
)

#: How far back to look for framing prose. Three lines covers a sentence
#: immediately before a fenced block without reaching into unrelated sections.
_FRAMING_LOOKBACK_LINES = 4

_FENCE_LINE = re.compile(r"^\s*```")


#: How far forward to look. Framing frequently follows the pattern within the
#: same sentence — "if you see `git push --force main`, stop and escalate".
_FRAMING_LOOKAHEAD_CHARS = 160

#: A deliberately narrower set for the forward window. The backward set includes
#: broad terms like "avoid" and "do not", which are fine *before* a pattern but
#: catastrophic after it: "Do not tell the user" would frame itself, and
#: "--dangerously-skip-permissions to avoid prompts" would frame itself too.
#: Only phrasing that unambiguously reacts to a preceding example belongs here.
_TRAILING_FRAMING = re.compile(
    r"\b(?:stop\s+and\s+(?:escalate|ask|refuse|report)|escalate|report\s+it|"
    r"is\s+(?:an\s+)?(?:attack|malicious|a\s+red\s+flag|an\s+indicator|dangerous)|"
    r"should\s+never\s+appear|indicates?\s+(?:a\s+)?(?:compromise|attack)|"
    r"means?\s+the\s+skill\s+is|do\s+not\s+run\s+(?:this|it|them)|never\s+run\s+(?:this|it|them))",
    re.IGNORECASE,
)


def documentation_framed(text: str, offset: int, end: int | None = None) -> bool:
    """True when the content at ``offset`` is framed as documentation.

    Looks backwards from the match — past the opening fence if it is inside a
    code block, then over the preceding few lines of prose — and forwards from
    the *end* of the match to the end of its sentence. Requires an explicit
    framing signal, so ordinary instructions are unaffected.
    """
    # Forward window: the remainder of the sentence *after* the match. Starting
    # at the match itself would let a payload frame itself with its own words.
    tail_start = end if end is not None else offset
    tail = text[tail_start : tail_start + _FRAMING_LOOKAHEAD_CHARS]
    sentence_end = min(
        (index for index in (tail.find("."), tail.find("\n\n")) if index != -1),
        default=len(tail),
    )
    if _TRAILING_FRAMING.search(tail[: sentence_end + 1]):
        return True

    prefix = text[:offset]
    lines = prefix.split("\n")

    # If we are inside a fenced block, step back to the prose above the fence so
    # that "Never run these:" followed by a block of attacks is recognised.
    fence_lines = [index for index, line in enumerate(lines) if _FENCE_LINE.match(line)]
    # An odd number of fences before this point means the offset is inside a
    # code block; the most recent fence is the one that opened it.
    inside_fence = len(fence_lines) % 2 == 1
    end = fence_lines[-1] if (inside_fence and fence_lines) else len(lines)

    window = "\n".join(lines[max(0, end - _FRAMING_LOOKBACK_LINES) : end])
    if _FRAMING_SIGNALS.search(window):
        return True

    # A heading anywhere above that frames the section (e.g. "## What not to do",
    # "## Attack patterns") also counts, but only the nearest one.
    for index in range(min(end, len(lines)) - 1, -1, -1):
        line = lines[index]
        if line.startswith("#"):
            return bool(_FRAMING_SIGNALS.search(line))
    return False


def first(iterator: Iterator[Match]) -> Match | None:
    return next(iterator, None)


def compile_any(*patterns: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    """Compile alternated patterns into one, keeping each branch anchored."""
    return re.compile("|".join(f"(?:{p})" for p in patterns), flags)


#: Severity ladder, most severe first, used by the documentation downgrade.
_SEVERITY_LADDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def emit_match(
    rule_id: str,
    skill: str,
    match: Match,
    *,
    message: str = "",
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    note: str = "",
    steps: int = 2,
) -> Finding:
    """Emit a finding for ``match``, downgrading it if it is documentation.

    A pattern that appears under prose framing it as an attack example is still
    reported — dropping evidence silently is worse than reporting it quietly —
    but it drops ``steps`` severity levels and to LOW confidence, so it informs
    a reader without failing a build. The evidence note says why.
    """
    from skillsniff.rules.base import emit, registry

    if match.is_documented:
        meta = registry.meta(rule_id)
        base = severity or (meta.severity if meta else Severity.MEDIUM)
        index = _SEVERITY_LADDER.index(base) if base in _SEVERITY_LADDER else 2
        lowered = _SEVERITY_LADDER[min(index + steps, len(_SEVERITY_LADDER) - 1)]
        # Clamp to LOW at most. A documentation-framed match is a note, not a
        # defect: leaving it at MEDIUM would still fail a default gate, which
        # would mean a skill cannot document the attacks it teaches people to
        # find. The evidence is kept; only its weight is removed.
        severity = lowered if lowered.rank >= Severity.LOW.rank else Severity.LOW
        confidence = Confidence.LOW
        note = note or "appears under prose framing it as an example, not an instruction"

    return emit(
        rule_id,
        skill,
        message=message or f"{match.path}: {match.excerpt!r}",
        evidence=[match.evidence(note=note)],
        severity=severity,
        confidence=confidence,
    )
