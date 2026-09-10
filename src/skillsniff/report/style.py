"""Terminal styling primitives.

Colour is opt-out and auto-detected. NO_COLOR is honoured because it is the
convention, and because security output frequently ends up in log aggregators
where escape codes are noise.
"""

from __future__ import annotations

import os
import shutil
import sys

from skillsniff.model.finding import Confidence, Severity
from skillsniff.model.result import RiskBand, Verdict

RESET = "\033[0m"

_CODES = {
    "critical": "\033[1;35m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[0;36m",
    "info": "\033[0;37m",
    "ok": "\033[1;32m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "underline": "\033[4m",
}

VERDICT_STYLE = {
    Verdict.BLOCK: "critical",
    Verdict.REVIEW: "high",
    Verdict.CAUTION: "medium",
    Verdict.CLEAR: "ok",
    Verdict.INCONCLUSIVE: "medium",
}

BAND_STYLE = {
    RiskBand.CRITICAL: "critical",
    RiskBand.HIGH: "high",
    RiskBand.MEDIUM: "medium",
    RiskBand.LOW: "low",
    RiskBand.NONE: "ok",
}


def supports_color(stream=None, force: bool | None = None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


class Style:
    """Applies (or strips) ANSI styling based on one decision made up front."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, style: str) -> str:
        if not self.enabled or style not in _CODES:
            return text
        return f"{_CODES[style]}{text}{RESET}"

    def severity(self, severity: Severity, text: str | None = None) -> str:
        return self(text or severity.value, severity.value)

    def verdict(self, verdict: Verdict, text: str | None = None) -> str:
        return self(text or verdict.value, VERDICT_STYLE[verdict])

    def band(self, band: RiskBand, text: str | None = None) -> str:
        return self(text or band.value, BAND_STYLE[band])

    def confidence(self, confidence: Confidence) -> str:
        return self(confidence.value, "dim" if confidence is Confidence.LOW else "info")


def width(default: int = 100) -> int:
    try:
        return min(shutil.get_terminal_size((default, 24)).columns, 120)
    except OSError:
        return default


def wrap(text: str, limit: int, indent: str = "") -> list[str]:
    """Greedy word wrap that never splits a word."""
    words = text.split()
    if not words:
        return []
    lines: list[str] = []
    current = indent
    for word in words:
        candidate = f"{current}{word}" if current == indent else f"{current} {word}"
        if len(candidate) > limit and current != indent:
            lines.append(current)
            current = f"{indent}{word}"
        else:
            current = candidate
    if current.strip():
        lines.append(current)
    return lines


def truncate(text: str, limit: int) -> str:
    text = text.replace("\n", " ").replace("\r", "")
    return text if len(text) <= limit else text[: limit - 1] + "…"
