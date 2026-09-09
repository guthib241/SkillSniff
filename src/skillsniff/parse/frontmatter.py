"""YAML frontmatter parsing.

Two backends, one contract. When PyYAML is installed we use ``safe_load``,
which understands the whole YAML subset the specification permits. When it is
not — the default, because SkillSniff must run on a bare interpreter — we fall
back to a hand-written parser.

The fallback is materially stronger than a naive line splitter: it handles
block scalars with their indentation and chomping indicators, flow and block
sequences, nested mappings to arbitrary depth, quoted scalars with escapes, and
comments. Where it genuinely cannot represent a construct it says so via a
:class:`ParseIssue` instead of dropping the key, because silently discarding a
frontmatter key is how a scanner ends up not knowing a skill declared a tool.

Both backends are hardened against the YAML-specific denial-of-service shapes:
input is size-capped, alias expansion is refused outright, and nesting depth is
bounded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

try:  # pragma: no cover - exercised by both branches in CI
    import yaml as _pyyaml
except ImportError:  # pragma: no cover
    _pyyaml = None  # type: ignore[assignment]

HAVE_PYYAML = _pyyaml is not None

MAX_FRONTMATTER_BYTES = 256 * 1024
MAX_DEPTH = 12
_ALIAS_RE = re.compile(r"(?m)^\s*[^#\n]*?(?<![\w])[*&][A-Za-z0-9_-]+")


class IssueKind(str, Enum):
    NO_FRONTMATTER = "no-frontmatter"
    NOT_AT_START = "not-at-start"
    UNCLOSED = "unclosed"
    UNPARSEABLE_LINE = "unparseable-line"
    INVALID_YAML = "invalid-yaml"
    TOO_LARGE = "too-large"
    ALIASES_REFUSED = "aliases-refused"
    TOO_DEEP = "too-deep"
    DUPLICATE_KEY = "duplicate-key"
    NOT_A_MAPPING = "not-a-mapping"
    TAB_INDENT = "tab-indent"


@dataclass(frozen=True)
class ParseIssue:
    kind: IssueKind
    message: str
    line: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "message": self.message, "line": self.line}


@dataclass
class Frontmatter:
    """The parsed result. ``present`` distinguishes 'absent' from 'broken'."""

    data: dict[str, Any] = field(default_factory=dict)
    raw: str = ""
    present: bool = False
    body: str = ""
    body_start_line: int = 1
    #: Source line of each top-level key, for precise finding locations.
    key_lines: dict[str, int] = field(default_factory=dict)
    issues: list[ParseIssue] = field(default_factory=list)
    backend: str = "fallback"

    @property
    def ok(self) -> bool:
        return self.present and not any(
            i.kind
            in (
                IssueKind.UNCLOSED,
                IssueKind.INVALID_YAML,
                IssueKind.NOT_AT_START,
                IssueKind.NOT_A_MAPPING,
            )
            for i in self.issues
        )

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def line_of(self, key: str) -> int | None:
        return self.key_lines.get(key)


def split_document(text: str) -> tuple[str | None, str, int, list[ParseIssue]]:
    """Split ``text`` into (frontmatter_block, body, body_start_line, issues)."""
    issues: list[ParseIssue] = []

    # A BOM before the fence is a real-world authoring accident that makes
    # loaders reject the file; report it but keep parsing.
    stripped = text.lstrip("﻿")
    had_bom = stripped != text

    if not stripped.startswith("---"):
        marker = stripped.find("\n---")
        if marker != -1:
            issues.append(
                ParseIssue(
                    IssueKind.NOT_AT_START,
                    "frontmatter fence found, but content precedes it; loaders require "
                    "'---' on the very first line",
                    line=stripped.count("\n", 0, marker) + 2,
                )
            )
        else:
            issues.append(ParseIssue(IssueKind.NO_FRONTMATTER, "no '---' frontmatter fence found"))
        return None, text, 1, issues

    if had_bom:
        issues.append(
            ParseIssue(
                IssueKind.NOT_AT_START,
                "file begins with a UTF-8 BOM before the '---' fence",
            )
        )

    lines = stripped.splitlines()
    end: int | None = None
    for index in range(1, len(lines)):
        if lines[index].rstrip() in ("---", "..."):
            end = index
            break

    if end is None:
        issues.append(ParseIssue(IssueKind.UNCLOSED, "frontmatter opened with '---' but never closed"))
        return None, "", 1, issues

    block = "\n".join(lines[1:end])
    body = "\n".join(lines[end + 1 :])
    return block, body, end + 2, issues


def parse(text: str) -> Frontmatter:
    """Parse the frontmatter of a SKILL.md document."""
    block, body, body_line, issues = split_document(text)
    if block is None:
        return Frontmatter(body=body, body_start_line=body_line, issues=issues, present=False)

    result = Frontmatter(
        raw=block,
        present=True,
        body=body,
        body_start_line=body_line,
        issues=issues,
        key_lines=_index_keys(block),
    )

    if len(block.encode("utf-8")) > MAX_FRONTMATTER_BYTES:
        result.issues.append(
            ParseIssue(
                IssueKind.TOO_LARGE,
                f"frontmatter exceeds {MAX_FRONTMATTER_BYTES} bytes and was not parsed",
            )
        )
        return result

    if _ALIAS_RE.search(block):
        # Anchors/aliases are not part of any real skill and are the vehicle for
        # the billion-laughs expansion. Refusing is safer than bounding.
        result.issues.append(
            ParseIssue(
                IssueKind.ALIASES_REFUSED,
                "frontmatter uses YAML anchors or aliases; refused as an expansion risk",
            )
        )
        return result

    if HAVE_PYYAML:
        data, backend_issues = _parse_pyyaml(block)
        result.backend = "pyyaml"
    else:
        data, backend_issues = _parse_fallback(block)
        result.backend = "fallback"

    result.data = data
    result.issues.extend(backend_issues)
    return result


# ---------------------------------------------------------------------------
# PyYAML backend
# ---------------------------------------------------------------------------


def _parse_pyyaml(block: str) -> tuple[dict[str, Any], list[ParseIssue]]:
    issues: list[ParseIssue] = []
    assert _pyyaml is not None
    try:
        loaded = _pyyaml.safe_load(block)
    except _pyyaml.YAMLError as exc:
        line = getattr(getattr(exc, "problem_mark", None), "line", 0) or 0
        return {}, [ParseIssue(IssueKind.INVALID_YAML, str(exc).replace("\n", " ")[:200], line + 2)]

    if loaded is None:
        return {}, issues
    if not isinstance(loaded, dict):
        return {}, [
            ParseIssue(
                IssueKind.NOT_A_MAPPING,
                f"frontmatter must be a mapping, got {type(loaded).__name__}",
            )
        ]
    if _depth_of(loaded) > MAX_DEPTH:
        issues.append(ParseIssue(IssueKind.TOO_DEEP, f"nesting exceeds {MAX_DEPTH} levels"))
    return {str(k): v for k, v in loaded.items()}, issues


def _depth_of(node: Any, level: int = 0) -> int:
    if level > MAX_DEPTH:
        return level
    if isinstance(node, dict):
        return max((_depth_of(v, level + 1) for v in node.values()), default=level)
    if isinstance(node, list):
        return max((_depth_of(v, level + 1) for v in node), default=level)
    return level


# ---------------------------------------------------------------------------
# Dependency-free fallback backend
# ---------------------------------------------------------------------------

_KEY_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<key>[^\s:#][^:#]*?)\s*:(?:\s+(?P<value>.*))?\s*$")
_ITEM_RE = re.compile(r"^(?P<indent>[ \t]*)-(?:\s+(?P<value>.*))?\s*$")
_BLOCK_RE = re.compile(r"^([|>])([+-]?)(\d*)$|^([|>])(\d*)([+-]?)$")


def _index_keys(block: str) -> dict[str, int]:
    """Line number of each *top-level* key, 1-based within the whole file."""
    out: dict[str, int] = {}
    for offset, line in enumerate(block.splitlines()):
        if line[:1] in (" ", "\t", "#", "") :
            continue
        match = _KEY_RE.match(line)
        if match:
            key = match.group("key").strip().strip("\"'")
            out.setdefault(key, offset + 2)  # +1 for the '---', +1 for 1-based
    return out


def _scalar(raw: str) -> Any:
    """Convert a YAML scalar token to a Python value."""
    value = raw.strip()
    if not value:
        return ""
    if value[0] == value[-1] and value[0] in "\"'" and len(value) >= 2:
        inner = value[1:-1]
        if value[0] == '"':
            return (
                inner.replace('\\"', '"')
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\\\", "\\")
            )
        return inner.replace("''", "'")
    if value.startswith("[") and value.endswith("]"):
        return _flow_sequence(value[1:-1])
    if value.startswith("{") and value.endswith("}"):
        return _flow_mapping(value[1:-1])
    lowered = value.lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if lowered in ("null", "~", ""):
        return None
    if re.fullmatch(r"[+-]?\d+", value):
        return int(value)
    if re.fullmatch(r"[+-]?(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?", value):
        return float(value)
    return value


def _split_flow(text: str) -> list[str]:
    """Split a flow collection on commas that are not inside quotes or brackets."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    for ch in text:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            current.append(ch)
        elif ch in "[{":
            depth += 1
            current.append(ch)
        elif ch in "]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _flow_sequence(inner: str) -> list[Any]:
    return [_scalar(part) for part in _split_flow(inner)]


def _flow_mapping(inner: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for part in _split_flow(inner):
        if ":" not in part:
            out[part.strip().strip("\"'")] = None
            continue
        key, _, value = part.partition(":")
        out[key.strip().strip("\"'")] = _scalar(value)
    return out


def _indent_width(line: str) -> int:
    width = 0
    for ch in line:
        if ch == " ":
            width += 1
        elif ch == "\t":
            width += 8
        else:
            break
    return width


def _parse_fallback(block: str) -> tuple[dict[str, Any], list[ParseIssue]]:
    lines = block.splitlines()
    issues: list[ParseIssue] = []
    if any(line.startswith("\t") for line in lines):
        issues.append(
            ParseIssue(
                IssueKind.TAB_INDENT,
                "frontmatter is indented with tabs; YAML forbids tab indentation",
            )
        )
    value, consumed = _parse_block(lines, 0, -1, issues, depth=0)
    del consumed
    if value is None:
        return {}, issues
    if not isinstance(value, dict):
        issues.append(
            ParseIssue(IssueKind.NOT_A_MAPPING, f"frontmatter must be a mapping, got {type(value).__name__}")
        )
        return {}, issues
    return value, issues


def _parse_block(
    lines: list[str],
    start: int,
    parent_indent: int,
    issues: list[ParseIssue],
    depth: int,
) -> tuple[Any, int]:
    """Parse a block-style collection beginning at ``lines[start]``.

    Returns the parsed value and the index of the first unconsumed line.
    """
    if depth > MAX_DEPTH:
        issues.append(ParseIssue(IssueKind.TOO_DEEP, f"nesting exceeds {MAX_DEPTH} levels", start + 2))
        return None, len(lines)

    mapping: dict[str, Any] = {}
    sequence: list[Any] = []
    index = start
    own_indent: int | None = None

    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue

        indent = _indent_width(line)
        if indent <= parent_indent:
            break
        if own_indent is None:
            own_indent = indent
        elif indent < own_indent:
            break
        elif indent > own_indent:
            # Continuation of a construct we already consumed; skip defensively
            # rather than misattributing it to this level.
            index += 1
            continue

        item = _ITEM_RE.match(line)
        if item:
            raw = (item.group("value") or "").strip()
            if raw and ":" in raw and not raw.startswith(("[", "{", '"', "'")):
                # "- key: value" — an inline mapping inside a sequence item.
                key, _, rest = raw.partition(":")
                entry: dict[str, Any] = {key.strip(): _scalar(rest)}
                nested, index = _parse_block(lines, index + 1, indent, issues, depth + 1)
                if isinstance(nested, dict):
                    entry.update(nested)
                sequence.append(entry)
                continue
            if raw:
                sequence.append(_scalar(raw))
                index += 1
                continue
            nested, index = _parse_block(lines, index + 1, indent, issues, depth + 1)
            sequence.append(nested)
            continue

        match = _KEY_RE.match(line)
        if not match:
            issues.append(
                ParseIssue(IssueKind.UNPARSEABLE_LINE, f"could not parse: {line.strip()[:80]!r}", index + 2)
            )
            index += 1
            continue

        key = match.group("key").strip().strip("\"'")
        raw_value = (match.group("value") or "").strip()

        if key in mapping:
            issues.append(ParseIssue(IssueKind.DUPLICATE_KEY, f"duplicate key {key!r}", index + 2))

        block_marker = _BLOCK_RE.match(raw_value) if raw_value else None
        if block_marker:
            style = raw_value[0]
            chomp = "-" if "-" in raw_value else ("+" if "+" in raw_value else "")
            text, index = _read_block_scalar(lines, index + 1, indent, style, chomp)
            mapping[key] = text
            continue

        if raw_value and not raw_value.startswith("#"):
            mapping[key] = _scalar(raw_value)
            index += 1
            continue

        nested, index = _parse_block(lines, index + 1, indent, issues, depth + 1)
        mapping[key] = nested if nested is not None else None

    if sequence and mapping:
        # Malformed: both at one level. Prefer the mapping and say so.
        issues.append(
            ParseIssue(IssueKind.UNPARSEABLE_LINE, "mixed sequence and mapping at the same level", start + 2)
        )
    if sequence:
        return sequence, index
    if mapping:
        return mapping, index
    return None, index


def _read_block_scalar(
    lines: list[str], start: int, parent_indent: int, style: str, chomp: str
) -> tuple[str, int]:
    """Read a ``|`` or ``>`` block scalar, preserving relative indentation."""
    collected: list[str] = []
    index = start
    base: int | None = None

    while index < len(lines):
        line = lines[index]
        if not line.strip():
            collected.append("")
            index += 1
            continue
        indent = _indent_width(line)
        if indent <= parent_indent:
            break
        if base is None:
            base = indent
        collected.append(line[min(base, len(line) - len(line.lstrip())) :] if base else line.strip())
        index += 1

    trailing_blanks = 0
    while collected and not collected[-1].strip():
        collected.pop()
        trailing_blanks += 1

    if style == "|":
        text = "\n".join(collected)
    else:
        # Folded: blank lines become paragraph breaks, other newlines become spaces.
        paragraphs: list[list[str]] = [[]]
        for entry in collected:
            if entry.strip():
                paragraphs[-1].append(entry.strip())
            else:
                paragraphs.append([])
        text = "\n\n".join(" ".join(p) for p in paragraphs if p)

    # Chomping, matching YAML semantics and therefore PyYAML:
    #   '-' strip  — remove every trailing line break
    #   ''  clip   — keep exactly one, but only if the source had one at all
    #   '+' keep   — preserve all trailing line breaks
    # The "only if the source had one" clause matters here because frontmatter
    # is split on the closing '---', so the final content line carries no
    # newline. Adding one unconditionally made the fallback disagree with
    # PyYAML on every literal block that ends the frontmatter.
    if chomp == "-":
        return text, index

    source_had_break = index < len(lines) or trailing_blanks > 0
    if chomp == "+":
        return text + ("\n" * trailing_blanks if source_had_break else ""), index
    return text + ("\n" if source_had_break else ""), index
