"""Baseline suppression.

The practical barrier to adopting any new analyser on an existing repository is
that day one it reports everything at once. A team that cannot get to zero
findings in one sitting will turn the gate off, and then it never comes back on.

A baseline records the findings that exist today so the gate can be enabled
immediately and enforce only what happens *next*. Three properties make this
safe rather than a way to hide problems:

*Fingerprints ignore line numbers.* A finding is identified by rule, file, and a
normalised form of its evidence — not its position — so reformatting a file does
not resurrect every suppressed finding, and moving code does not mask a new one.

*Counts are respected.* If a baseline records two `EXE003` findings in a file and
a third appears, the third is reported. Suppression is per occurrence, not
per rule-and-file.

*Suppression is always visible.* Every report states how many findings the
baseline hid. A silent baseline is indistinguishable from a broken scanner.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skillsniff import __version__
from skillsniff.core.errors import UsageError
from skillsniff.model.finding import Finding

BASELINE_VERSION = "1"
DEFAULT_BASELINE_NAME = "skillsniff-baseline.json"

#: Runs of digits, hex, and whitespace are normalised out of the excerpt before
#: hashing. A finding whose evidence differs only by a line number, a timestamp,
#: or reindentation is the same finding.
_VOLATILE = re.compile(r"\s+|\b[0-9a-f]{8,}\b|\b\d+\b", re.IGNORECASE)


def fingerprint(finding: Finding) -> str:
    """A stable identity for one finding, independent of its position.

    Deliberately excludes the line number. Including it would mean a single
    added import at the top of a file un-suppresses everything below it, which
    makes a baseline useless in practice — and teams respond to that by
    regenerating the baseline, which is how a real finding gets buried.
    """
    primary = finding.primary
    path = primary.path if primary else ""
    excerpt = primary.excerpt if primary else ""
    normalised = _VOLATILE.sub(" ", excerpt).strip().lower()

    digest = hashlib.sha256()
    for part in (finding.rule_id, finding.skill, path, normalised):
        digest.update(f"{len(part)}:{part}|".encode())
    return digest.hexdigest()[:24]


@dataclass
class Baseline:
    """Recorded findings, counted by fingerprint."""

    counts: Counter[str] = field(default_factory=Counter)
    generated_at: str = ""
    tool_version: str = ""
    #: Human-readable context per fingerprint, so the file can be reviewed.
    notes: dict[str, str] = field(default_factory=dict)
    source: Path | None = None

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> Baseline:
        baseline = cls(
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            tool_version=__version__,
        )
        for finding in findings:
            key = fingerprint(finding)
            baseline.counts[key] += 1
            baseline.notes.setdefault(
                key,
                f"{finding.rule_id} {finding.severity.value} {finding.location} — {finding.title}",
            )
        return baseline

    def as_dict(self) -> dict[str, Any]:
        return {
            "baseline_version": BASELINE_VERSION,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "total": self.total,
            "note": (
                "Findings recorded here are suppressed by --baseline. Every report states "
                "how many were hidden. Remove an entry to start enforcing it; regenerate "
                "this file only when you have deliberately accepted new findings."
            ),
            "findings": [
                {"fingerprint": key, "count": count, "note": self.notes.get(key, "")}
                for key, count in sorted(self.counts.items())
            ],
        }

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.as_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def read(cls, path: Path) -> Baseline:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise UsageError(f"cannot read baseline {path}: {exc}") from exc
        except (json.JSONDecodeError, ValueError) as exc:
            raise UsageError(f"baseline {path} is not valid JSON: {exc}") from exc

        if not isinstance(data, dict) or "baseline_version" not in data:
            raise UsageError(f"{path} does not look like a SkillSniff baseline")
        if str(data["baseline_version"]) != BASELINE_VERSION:
            raise UsageError(
                f"baseline version {data['baseline_version']} is not supported by this build "
                f"(expected {BASELINE_VERSION}); regenerate it with 'skillsniff baseline'"
            )

        baseline = cls(
            generated_at=str(data.get("generated_at", "")),
            tool_version=str(data.get("tool_version", "")),
            source=path,
        )
        entries = data.get("findings", [])
        if not isinstance(entries, list):
            raise UsageError(f"{path}: 'findings' must be a list")
        for entry in entries:
            if not isinstance(entry, dict) or "fingerprint" not in entry:
                continue
            key = str(entry["fingerprint"])
            baseline.counts[key] += int(entry.get("count", 1))
            if entry.get("note"):
                baseline.notes.setdefault(key, str(entry["note"]))
        return baseline


@dataclass
class Applied:
    """The result of filtering findings through a baseline."""

    kept: list[Finding] = field(default_factory=list)
    suppressed: int = 0
    #: Baseline entries that matched nothing — findings that have been fixed.
    stale: list[str] = field(default_factory=list)

    @property
    def has_stale(self) -> bool:
        return bool(self.stale)


def apply(baseline: Baseline, findings: list[Finding]) -> Applied:
    """Filter ``findings`` through ``baseline``, respecting recorded counts."""
    remaining = Counter(baseline.counts)
    result = Applied()

    # Sort so that when a baseline records fewer occurrences than exist, the
    # ones reported are the most severe rather than an arbitrary subset.
    for finding in sorted(findings, key=lambda f: f.sort_key()):
        key = fingerprint(finding)
        if remaining.get(key, 0) > 0:
            remaining[key] -= 1
            result.suppressed += 1
            continue
        result.kept.append(finding)

    result.stale = sorted(key for key, count in remaining.items() if count > 0)
    return result
