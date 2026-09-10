"""Resource limits and the coverage ledger.

A security scanner that can be made to hang, exhaust memory, or silently skip
content is worse than no scanner, because it reports "clean" on the artifact
that defeated it. Every limit here exists because an attacker controls the
input, and every limit that *bites* is recorded so the report can downgrade its
own confidence instead of lying.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

# Defaults chosen to comfortably fit real skills while refusing pathological
# input. A legitimate SKILL.md is a few kilobytes; a 10 MB one is an attack or a
# mistake, and either way deserves a finding rather than a 30-second scan.
DEFAULT_MAX_FILE_BYTES = 5 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_FILES = 2_000
DEFAULT_MAX_ARCHIVE_DEPTH = 3
DEFAULT_MAX_ARCHIVE_ENTRIES = 1_000
DEFAULT_MAX_ARCHIVE_RATIO = 100  # decompression-bomb guard
DEFAULT_MAX_DECODE_DEPTH = 3
DEFAULT_TIME_BUDGET_SECONDS = 60.0
DEFAULT_MAX_REGEX_INPUT = 1 * 1024 * 1024


class CoverageReason(str, Enum):
    """Why a piece of content was not fully analysed."""

    FILE_TOO_LARGE = "file-too-large"
    TOTAL_BYTES_EXCEEDED = "total-bytes-exceeded"
    FILE_COUNT_EXCEEDED = "file-count-exceeded"
    ARCHIVE_TOO_DEEP = "archive-too-deep"
    ARCHIVE_TOO_MANY_ENTRIES = "archive-too-many-entries"
    DECOMPRESSION_BOMB = "decompression-bomb"
    TIME_BUDGET_EXCEEDED = "time-budget-exceeded"
    UNREADABLE = "unreadable"
    UNPARSEABLE = "unparseable"
    BINARY = "binary"
    ENCRYPTED_ARCHIVE = "encrypted-archive"
    UNSAFE_PATH = "unsafe-path"
    SYMLINK_SKIPPED = "symlink-skipped"
    EXCLUDED = "excluded"


@dataclass(frozen=True)
class Limits:
    """Immutable resource budget for one scan."""

    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_files: int = DEFAULT_MAX_FILES
    max_archive_depth: int = DEFAULT_MAX_ARCHIVE_DEPTH
    max_archive_entries: int = DEFAULT_MAX_ARCHIVE_ENTRIES
    max_archive_ratio: int = DEFAULT_MAX_ARCHIVE_RATIO
    max_decode_depth: int = DEFAULT_MAX_DECODE_DEPTH
    time_budget_seconds: float = DEFAULT_TIME_BUDGET_SECONDS
    max_regex_input: int = DEFAULT_MAX_REGEX_INPUT
    follow_symlinks: bool = False

    @classmethod
    def unlimited(cls) -> Limits:
        """A deliberately permissive budget, for trusted local corpora only."""
        return cls(
            max_file_bytes=1 << 30,
            max_total_bytes=1 << 34,
            max_files=1_000_000,
            max_archive_depth=8,
            max_archive_entries=100_000,
            max_archive_ratio=10_000,
            max_decode_depth=6,
            time_budget_seconds=3600.0,
            max_regex_input=1 << 26,
        )


@dataclass
class CoverageGap:
    """One thing the scanner could not fully inspect."""

    path: str
    reason: CoverageReason
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "reason": self.reason.value, "detail": self.detail}


@dataclass
class Budget:
    """Mutable accounting against a :class:`Limits` for a single scan.

    Callers ask permission (``allow_file``) rather than being trusted to check
    limits themselves, so there is exactly one place where a limit can be
    forgotten.
    """

    limits: Limits = field(default_factory=Limits)
    bytes_read: int = 0
    files_read: int = 0
    files_analyzed: int = 0
    files_discovered: int = 0
    archives_expanded: int = 0
    encoded_regions_inspected: int = 0
    gaps: list[CoverageGap] = field(default_factory=list)
    started_at: float = field(default_factory=time.monotonic)

    # -- accounting ---------------------------------------------------------

    def note_gap(self, path: str, reason: CoverageReason, detail: str = "") -> None:
        self.gaps.append(CoverageGap(path=path, reason=reason, detail=detail))

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def time_exhausted(self) -> bool:
        return self.elapsed > self.limits.time_budget_seconds

    def allow_file(self, path: str, size: int) -> bool:
        """Return True if a file of ``size`` bytes may be read.

        Records a coverage gap and returns False when it may not, so a refusal
        is always visible in the report.
        """
        if self.time_exhausted():
            self.note_gap(path, CoverageReason.TIME_BUDGET_EXCEEDED, f"{self.elapsed:.1f}s elapsed")
            return False
        if self.files_read >= self.limits.max_files:
            self.note_gap(path, CoverageReason.FILE_COUNT_EXCEEDED, f"limit {self.limits.max_files}")
            return False
        if size > self.limits.max_file_bytes:
            self.note_gap(
                path,
                CoverageReason.FILE_TOO_LARGE,
                f"{size} bytes exceeds {self.limits.max_file_bytes}",
            )
            return False
        if self.bytes_read + size > self.limits.max_total_bytes:
            self.note_gap(
                path,
                CoverageReason.TOTAL_BYTES_EXCEEDED,
                f"limit {self.limits.max_total_bytes}",
            )
            return False
        self.files_read += 1
        self.bytes_read += size
        return True

    # -- coverage summary ---------------------------------------------------

    @property
    def has_gaps(self) -> bool:
        return bool(self.gaps)

    def confidence(self) -> str:
        """Coverage confidence: HIGH, MEDIUM, or LOW.

        This is confidence in *how much was inspected*, not confidence that the
        skill is safe. They are different claims and conflating them is exactly
        the failure mode this project exists to avoid.
        """
        if not self.gaps:
            return "HIGH"
        blocking = {
            CoverageReason.TIME_BUDGET_EXCEEDED,
            CoverageReason.FILE_COUNT_EXCEEDED,
            CoverageReason.TOTAL_BYTES_EXCEEDED,
            CoverageReason.ENCRYPTED_ARCHIVE,
            CoverageReason.DECOMPRESSION_BOMB,
            CoverageReason.ARCHIVE_TOO_DEEP,
        }
        if any(g.reason in blocking for g in self.gaps):
            return "LOW"
        analysed = self.files_analyzed
        total = max(self.files_discovered, analysed)
        if total and analysed / total < 0.9:
            return "LOW"
        return "MEDIUM"
