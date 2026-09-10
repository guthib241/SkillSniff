"""Text normalisation, Unicode threat analysis, and encoded-payload extraction.

Skill content is read by two very different consumers: a human reviewer looking
at rendered Markdown, and a language model reading the raw byte stream. Anything
that makes those two disagree is an attack primitive. This module makes the
disagreement measurable.

Three services are provided:

``analyze_unicode``
    Classify suspicious code points — zero-width, bidirectional overrides, Unicode
    tag characters, variation selectors, private-use, and script-mixing homoglyphs.

``decode_regions``
    Recursively extract and decode base64 / hex / percent / escape-encoded regions
    so rules can see through one or more layers of wrapping, with every decoded
    span still attributable to its byte offset in the original file.

``TextView``
    Bundles the raw text with a normalised view and a line index, so a finding
    discovered in a decoded or normalised projection still reports the line number
    a human can navigate to.

Limits: decoding is depth- and size-capped (see :mod:`skillsniff.core.limits`).
Confusable folding uses a curated table of the homoglyphs actually used in
attacks, not the full UTS #39 confusables set; this is documented as a known
limitation rather than presented as complete coverage.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# Unicode threat classes
# ---------------------------------------------------------------------------


class UnicodeThreat(str, Enum):
    ZERO_WIDTH = "zero-width"
    BIDI_CONTROL = "bidi-control"
    TAG_CHARACTER = "tag-character"
    VARIATION_SELECTOR = "variation-selector"
    PRIVATE_USE = "private-use"
    CONFUSABLE = "confusable"
    UNUSUAL_SPACE = "unusual-space"
    CONTROL = "control"


#: Zero-width and formatting characters that render as nothing but are read by
#: the model. The classic vehicle for instructions invisible to a reviewer.
ZERO_WIDTH_CHARS = frozenset(
    "​‌‍⁠⁡⁢⁣⁤﻿­᠎"
)

#: Bidirectional control characters. LRO/RLO/PDF and the isolate family can
#: reorder rendered text so that what a reviewer reads is not what is executed
#: (the "Trojan Source" class of attack).
BIDI_CHARS = frozenset("‪‫‬‭‮⁦⁧⁨⁩‎‏")

#: Unicode Tag characters (U+E0000–U+E007F). These mirror ASCII, render as
#: nothing in essentially every client, and are a documented channel for
#: smuggling instructions into a model's context.
TAG_BLOCK = range(0xE0000, 0xE0080)

VARIATION_SELECTORS = frozenset(chr(c) for c in list(range(0xFE00, 0xFE10)) + list(range(0xE0100, 0xE01F0)))

#: Whitespace that is not U+0020 but renders like it, used to break up keywords
#: that a naive scanner matches literally.
UNUSUAL_SPACES = frozenset(
    "           "
    "    　"
)

#: Curated homoglyph table: characters that look like ASCII but are not.
#: Restricted to the Cyrillic and Greek lookalikes that appear in real
#: typosquatting and evasion, plus a few maths-alphanumeric ranges.
CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s", "һ": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I", "Ѕ": "S", "Ј": "J",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Armenian / Cherokee lookalikes seen in the wild
    "օ": "o", "Ꭰ": "D", "Ꮐ": "G",
    # Fullwidth forms
    **{chr(0xFF21 + i): chr(ord("A") + i) for i in range(26)},
    **{chr(0xFF41 + i): chr(ord("a") + i) for i in range(26)},
}


@dataclass(frozen=True)
class UnicodeFinding:
    """One suspicious code point (or run) located in the source text."""

    threat: UnicodeThreat
    codepoint: int
    offset: int
    line: int
    char_name: str
    context: str

    @property
    def display(self) -> str:
        return f"U+{self.codepoint:04X}"

    def as_dict(self) -> dict[str, object]:
        return {
            "threat": self.threat.value,
            "codepoint": self.display,
            "name": self.char_name,
            "offset": self.offset,
            "line": self.line,
            "context": self.context,
        }


def _char_name(ch: str) -> str:
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "UNNAMED"


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _context_around(text: str, offset: int, width: int = 24) -> str:
    start = max(0, offset - width)
    end = min(len(text), offset + width)
    snippet = text[start:end]
    # Render the invisible characters visibly so the excerpt is actually useful
    # in a terminal report rather than looking identical to benign text.
    return "".join(
        ch if ch.isprintable() and ch not in ZERO_WIDTH_CHARS and ch not in BIDI_CHARS
        else f"<U+{ord(ch):04X}>"
        for ch in snippet
    )


def analyze_unicode(text: str, *, detect_confusables: bool = True) -> list[UnicodeFinding]:
    """Classify every suspicious code point in ``text``.

    Confusable detection only fires on script *mixing* inside a single word —
    an all-Cyrillic word is ordinary Russian text, whereas ``сurl`` (Cyrillic
    es followed by Latin) is an evasion attempt.
    """
    out: list[UnicodeFinding] = []

    for offset, ch in enumerate(text):
        code = ord(ch)
        threat: UnicodeThreat | None = None

        if ch in ZERO_WIDTH_CHARS:
            threat = UnicodeThreat.ZERO_WIDTH
        elif ch in BIDI_CHARS:
            threat = UnicodeThreat.BIDI_CONTROL
        elif code in TAG_BLOCK:
            threat = UnicodeThreat.TAG_CHARACTER
        elif ch in VARIATION_SELECTORS:
            threat = UnicodeThreat.VARIATION_SELECTOR
        elif 0xE000 <= code <= 0xF8FF or 0xF0000 <= code <= 0x10FFFD:
            threat = UnicodeThreat.PRIVATE_USE
        elif ch in UNUSUAL_SPACES:
            threat = UnicodeThreat.UNUSUAL_SPACE
        elif unicodedata.category(ch) == "Cc" and ch not in "\t\n\r":
            threat = UnicodeThreat.CONTROL

        if threat is not None:
            out.append(
                UnicodeFinding(
                    threat=threat,
                    codepoint=code,
                    offset=offset,
                    line=_line_at(text, offset),
                    char_name=_char_name(ch),
                    context=_context_around(text, offset),
                )
            )

    if detect_confusables:
        out.extend(_find_mixed_script_words(text))

    return out


_WORD_RE = re.compile(r"[^\W\d_]{2,}", re.UNICODE)


def _script_of(ch: str) -> str:
    """Coarse script bucket, sufficient for mixed-script detection."""
    code = ord(ch)
    if code < 0x80:
        return "Latin"
    name = _char_name(ch)
    for script in ("CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "CHEROKEE", "LATIN"):
        if name.startswith(script):
            return script.capitalize()
    return "Other"


def _find_mixed_script_words(text: str) -> list[UnicodeFinding]:
    """Flag words that mix scripts *and* contain a known homoglyph.

    Requiring both conditions keeps ordinary multilingual prose quiet: a purely
    Cyrillic word is not suspicious, and a mixed-script word with no ASCII
    lookalike character is more likely to be a genuine loanword than an attack.
    """
    out: list[UnicodeFinding] = []
    for match in _WORD_RE.finditer(text):
        word = match.group(0)
        if word.isascii():
            continue
        scripts = {_script_of(c) for c in word}
        scripts.discard("Other")
        if len(scripts) < 2:
            continue
        for i, ch in enumerate(word):
            if ch in CONFUSABLE_MAP:
                offset = match.start() + i
                out.append(
                    UnicodeFinding(
                        threat=UnicodeThreat.CONFUSABLE,
                        codepoint=ord(ch),
                        offset=offset,
                        line=_line_at(text, offset),
                        char_name=_char_name(ch),
                        context=f"{word!r} mixes {'/'.join(sorted(scripts))}"
                        f" — {ch!r} looks like {CONFUSABLE_MAP[ch]!r}",
                    )
                )
                break
    return out


#: Translation tables, built once. `str.translate` runs in C, where the
#: equivalent generator expressions ran ~22 million Python-level iterations on a
#: 1 MB file and dominated the profile.
_CONFUSABLE_TABLE = str.maketrans(CONFUSABLE_MAP)
_STRIP_TABLE = str.maketrans(
    "",
    "",
    "".join(ZERO_WIDTH_CHARS | BIDI_CHARS | VARIATION_SELECTORS)
    + "".join(chr(c) for c in TAG_BLOCK),
)
_SPACE_TABLE = str.maketrans(dict.fromkeys(UNUSUAL_SPACES, " "))


def fold_confusables(text: str) -> str:
    """Map known homoglyphs onto their ASCII lookalikes."""
    return text.translate(_CONFUSABLE_TABLE)


def strip_invisible(text: str) -> str:
    """Remove zero-width, bidi, tag, and variation-selector characters."""
    return text.translate(_STRIP_TABLE)


def normalize(text: str) -> str:
    """Produce the 'what the model effectively reads' projection of ``text``.

    NFKC-normalise, drop invisibles, fold homoglyphs, and collapse exotic
    whitespace. Rules run against both this and the raw text: the raw text
    catches literal patterns, the normalised view catches evasion.
    """
    folded = text.translate(_STRIP_TABLE).translate(_CONFUSABLE_TABLE).translate(_SPACE_TABLE)
    return unicodedata.normalize("NFKC", folded)


def decode_tag_characters(text: str) -> str:
    """Recover the ASCII hidden in a Unicode Tag-character run, if any."""
    return "".join(chr(ord(ch) - 0xE0000) for ch in text if ord(ch) in TAG_BLOCK)


# ---------------------------------------------------------------------------
# Encoded payload extraction
# ---------------------------------------------------------------------------


class Encoding(str, Enum):
    BASE64 = "base64"
    BASE32 = "base32"
    HEX = "hex"
    PERCENT = "percent"
    ESCAPE = "escape"
    TAG_UNICODE = "tag-unicode"
    ROT13 = "rot13"


@dataclass
class DecodedRegion:
    """A decoded span, still attributable to its position in the original text."""

    encoding: Encoding
    text: str
    origin_start: int
    origin_end: int
    origin_line: int
    depth: int
    parent: DecodedRegion | None = field(default=None, repr=False)

    @property
    def chain(self) -> str:
        """Human-readable decode chain, e.g. ``base64 -> hex``."""
        parts: list[str] = []
        node: DecodedRegion | None = self
        while node is not None:
            parts.append(node.encoding.value)
            node = node.parent
        return " -> ".join(reversed(parts))

    def as_dict(self) -> dict[str, object]:
        return {
            "encoding": self.encoding.value,
            "chain": self.chain,
            "depth": self.depth,
            "line": self.origin_line,
            "preview": self.text[:200],
        }


# A base64 run must be reasonably long before it is worth decoding: short runs
# match ordinary words and produce nothing but noise.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}[\s:,]?){12,}")
_PERCENT_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){6,}")
_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|(?:\\u[0-9a-fA-F]{4}){4,}")
_B32_RE = re.compile(r"[A-Z2-7]{32,}={0,6}")

#: Decoded bytes must look like text to be worth reporting. Binary noise from a
#: false-positive base64 match is filtered out here rather than in every rule.
_PRINTABLE_RATIO = 0.85


def _looks_like_text(data: bytes) -> str | None:
    if not data or len(data) < 6:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    if printable / len(text) < _PRINTABLE_RATIO:
        return None
    return text


def _try_base64(blob: str, urlsafe: bool = False) -> str | None:
    candidate = blob.strip()
    padding = (-len(candidate)) % 4
    candidate += "=" * padding
    try:
        raw = (
            base64.urlsafe_b64decode(candidate)
            if urlsafe
            else base64.b64decode(candidate, validate=True)
        )
    except (binascii.Error, ValueError):
        return None
    return _looks_like_text(raw)


def _try_hex(blob: str) -> str | None:
    cleaned = re.sub(r"[\s:,]|0x", "", blob)
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        return _looks_like_text(bytes.fromhex(cleaned))
    except ValueError:
        return None


def _try_percent(blob: str) -> str | None:
    try:
        return _looks_like_text(urllib.parse.unquote_to_bytes(blob))
    except (ValueError, UnicodeDecodeError):
        return None


def _try_escape(blob: str) -> str | None:
    try:
        decoded = blob.encode("ascii", "ignore").decode("unicode_escape")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None
    return decoded if decoded and decoded != blob else None


_DECODERS: list[tuple[Encoding, re.Pattern[str], object]] = [
    (Encoding.BASE64, _B64_RE, _try_base64),
    (Encoding.BASE32, _B32_RE, lambda b: _looks_like_text(_b32(b))),
    (Encoding.HEX, _HEX_RE, _try_hex),
    (Encoding.PERCENT, _PERCENT_RE, _try_percent),
    (Encoding.ESCAPE, _ESCAPE_RE, _try_escape),
]


def _b32(blob: str) -> bytes:
    candidate = blob.strip()
    candidate += "=" * ((-len(candidate)) % 8)
    try:
        return base64.b32decode(candidate)
    except (binascii.Error, ValueError):
        return b""


def decode_regions(
    text: str,
    *,
    max_depth: int = 3,
    max_regions: int = 64,
    _depth: int = 0,
    _parent: DecodedRegion | None = None,
    _origin: tuple[int, int, int] | None = None,
) -> list[DecodedRegion]:
    """Recursively extract decodable regions from ``text``.

    Returns every successfully decoded region, each carrying the offset and line
    of the *outermost* original span so findings remain navigable. Recursion is
    capped by ``max_depth`` and the total by ``max_regions``; both caps exist to
    stop a crafted input from turning the scan into an exponential decode.
    """
    if _depth >= max_depth:
        return []

    regions: list[DecodedRegion] = []

    hidden = decode_tag_characters(text)
    if hidden:
        offset = next((i for i, c in enumerate(text) if ord(c) in TAG_BLOCK), 0)
        start, end, line = _origin or (offset, offset + len(hidden), _line_at(text, offset))
        regions.append(
            DecodedRegion(
                encoding=Encoding.TAG_UNICODE,
                text=hidden,
                origin_start=start,
                origin_end=end,
                origin_line=line,
                depth=_depth,
                parent=_parent,
            )
        )

    for encoding, pattern, decoder in _DECODERS:
        for match in pattern.finditer(text):
            if len(regions) >= max_regions:
                return regions
            blob = match.group(0)
            decoded = decoder(blob)  # type: ignore[operator]
            if not decoded:
                continue
            start, end, line = _origin or (
                match.start(),
                match.end(),
                _line_at(text, match.start()),
            )
            region = DecodedRegion(
                encoding=encoding,
                text=decoded,
                origin_start=start,
                origin_end=end,
                origin_line=line,
                depth=_depth,
                parent=_parent,
            )
            regions.append(region)
            regions.extend(
                decode_regions(
                    decoded,
                    max_depth=max_depth,
                    max_regions=max_regions - len(regions),
                    _depth=_depth + 1,
                    _parent=region,
                    _origin=(start, end, line),
                )
            )

    return regions[:max_regions]


# ---------------------------------------------------------------------------
# TextView
# ---------------------------------------------------------------------------


@dataclass
class TextView:
    """Raw text plus every projection the rule engine needs.

    Built once per file so that normalisation and decoding are not repeated by
    every rule — the difference between a scan that takes 200 ms and one that
    takes 20 s on a large skill.
    """

    raw: str
    path: str = ""
    _normalized: str | None = field(default=None, repr=False)
    _decoded: list[DecodedRegion] | None = field(default=None, repr=False)
    _unicode: list[UnicodeFinding] | None = field(default=None, repr=False)
    max_decode_depth: int = 3

    @property
    def normalized(self) -> str:
        if self._normalized is None:
            self._normalized = normalize(self.raw)
        return self._normalized

    @property
    def decoded(self) -> list[DecodedRegion]:
        if self._decoded is None:
            self._decoded = decode_regions(self.raw, max_depth=self.max_decode_depth)
        return self._decoded

    @property
    def unicode_findings(self) -> list[UnicodeFinding]:
        if self._unicode is None:
            self._unicode = analyze_unicode(self.raw)
        return self._unicode

    def line_of(self, offset: int) -> int:
        return _line_at(self.raw, offset)

    def excerpt(self, start: int, end: int, limit: int = 120) -> str:
        """A single-line, length-capped excerpt suitable for a report."""
        snippet = self.raw[start:end].replace("\n", " ").strip()
        if len(snippet) > limit:
            snippet = snippet[: limit - 1] + "…"
        return snippet

    @property
    def is_differently_read(self) -> bool:
        """True when a human and a model plausibly read different text."""
        return strip_invisible(self.raw) != self.raw or fold_confusables(self.raw) != self.raw
