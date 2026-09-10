"""Lockfile verification.

Verification is not a hash comparison. A hash comparison answers "did anything
change", which on a living skill is almost always yes and therefore almost never
actionable. This answers "did anything *meaningful* change", and grades each
change by what it implies:

* a new privileged capability is CRITICAL — the skill can now do something it
  could not do when it was approved;
* a new external host or a dependency that became unpinned is HIGH;
* file content changes are MEDIUM, because they are where new behaviour comes
  from even when the capability set is unchanged;
* a verdict that got *better* is LOW, reported for completeness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillsniff.core.config import Config
from skillsniff.core.errors import UsageError
from skillsniff.model.capability import Capability
from skillsniff.provenance.lock import build_lock, read_lock


@dataclass
class Change:
    kind: str
    detail: str
    severity: str  # critical | high | medium | low
    before: str = ""
    after: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "severity": self.severity,
            **({"before": self.before} if self.before else {}),
            **({"after": self.after} if self.after else {}),
        }


@dataclass
class VerifyReport:
    skill: str
    locked_at: str
    ok: bool = True
    content_hash_matches: bool = True
    changes: list[Change] = field(default_factory=list)

    @property
    def worst(self) -> str:
        order = ["critical", "high", "medium", "low"]
        for level in order:
            if any(c.severity == level for c in self.changes):
                return level
        return "none"

    def as_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill,
            "locked_at": self.locked_at,
            "verified": self.ok,
            "content_hash_matches": self.content_hash_matches,
            "worst_change": self.worst,
            "changes": [c.as_dict() for c in self.changes],
        }


def _privileged(names: set[str]) -> set[str]:
    out = set()
    for name in names:
        try:
            if Capability(name).is_privileged:
                out.add(name)
        except ValueError:
            continue
    return out


def verify(path: Path, lockfile: Path, config: Config | None = None) -> VerifyReport:
    """Compare the skill at ``path`` against ``lockfile``."""
    if not lockfile.is_file():
        raise UsageError(
            f"no lockfile at {lockfile}; create one with 'skillsniff lock {path}'"
        )

    locked = read_lock(lockfile)
    current = build_lock(path, config)

    report = VerifyReport(
        skill=locked.get("skill", {}).get("name", path.name),
        locked_at=locked.get("generated_at", "unknown"),
    )

    report.content_hash_matches = locked.get("content_hash") == current["content_hash"]
    if report.content_hash_matches:
        return report

    # -- capabilities -------------------------------------------------------
    before_caps = set(locked.get("capabilities", []))
    after_caps = set(current["capabilities"])
    added = after_caps - before_caps
    removed = before_caps - after_caps

    for capability in sorted(_privileged(added)):
        report.changes.append(
            Change(
                kind="capability-added",
                detail=f"gained privileged capability {capability!r}",
                severity="critical",
                after=capability,
            )
        )
    for capability in sorted(added - _privileged(added)):
        report.changes.append(
            Change(kind="capability-added", detail=f"gained capability {capability!r}", severity="medium", after=capability)
        )
    for capability in sorted(removed):
        report.changes.append(
            Change(kind="capability-removed", detail=f"no longer uses {capability!r}", severity="low", before=capability)
        )

    # -- declared surface ---------------------------------------------------
    before_tools = set(locked.get("skill", {}).get("declared_tools", []))
    after_tools = set(current["skill"]["declared_tools"])
    for tool in sorted(after_tools - before_tools):
        report.changes.append(
            Change(kind="tool-declared", detail=f"declares new tool {tool!r}", severity="high", after=tool)
        )
    for tool in sorted(before_tools - after_tools):
        report.changes.append(
            Change(kind="tool-removed", detail=f"no longer declares {tool!r}", severity="low", before=tool)
        )

    if locked.get("skill", {}).get("description") != current["skill"]["description"]:
        report.changes.append(
            Change(
                kind="description-changed",
                detail="the stated purpose changed",
                severity="medium",
                before=(locked.get("skill", {}).get("description") or "")[:100],
                after=current["skill"]["description"][:100],
            )
        )
    elif added:
        # This is the pull-request-review case the diff command exists for: new
        # behaviour arriving under an unchanged description.
        report.changes.append(
            Change(
                kind="undeclared-change",
                detail="capabilities changed while the description did not",
                severity="high",
            )
        )

    # -- external resources -------------------------------------------------
    before_hosts = {r["host"]: r for r in locked.get("external_resources", [])}
    after_hosts = {r["host"]: r for r in current["external_resources"]}
    for host in sorted(set(after_hosts) - set(before_hosts)):
        report.changes.append(
            Change(
                kind="external-added",
                detail=f"now references {host} ({after_hosts[host]['trust']})",
                severity="high",
                after=host,
            )
        )
    for host in sorted(set(before_hosts) & set(after_hosts)):
        if before_hosts[host]["trust"] != after_hosts[host]["trust"]:
            report.changes.append(
                Change(
                    kind="external-trust-changed",
                    detail=f"{host} trust changed",
                    severity="medium",
                    before=before_hosts[host]["trust"],
                    after=after_hosts[host]["trust"],
                )
            )

    # -- dependencies -------------------------------------------------------
    before_deps = {(d["ecosystem"], d["name"]): d for d in locked.get("dependencies", [])}
    after_deps = {(d["ecosystem"], d["name"]): d for d in current["dependencies"]}
    for key in sorted(set(after_deps) - set(before_deps)):
        dependency = after_deps[key]
        report.changes.append(
            Change(
                kind="dependency-added",
                detail=f"added {dependency['name']} {dependency['version']} ({dependency['trust']})",
                severity="high" if dependency["trust"] in ("mutable", "suspicious") else "medium",
                after=dependency["name"],
            )
        )
    for key in sorted(set(before_deps) & set(after_deps)):
        before, after = before_deps[key], after_deps[key]
        if before["version"] != after["version"] or before["trust"] != after["trust"]:
            report.changes.append(
                Change(
                    kind="dependency-changed",
                    detail=f"{after['name']} {before['version']} → {after['version']}",
                    severity="high" if after["trust"] in ("mutable", "suspicious") else "medium",
                    before=f"{before['version']} ({before['trust']})",
                    after=f"{after['version']} ({after['trust']})",
                )
            )

    # -- files --------------------------------------------------------------
    before_files = {f["path"]: f["sha256"] for f in locked.get("files", [])}
    after_files = {f["path"]: f["sha256"] for f in current["files"]}
    for path_name in sorted(set(after_files) - set(before_files)):
        report.changes.append(
            Change(kind="file-added", detail=f"new file {path_name}", severity="medium", after=path_name)
        )
    for path_name in sorted(set(before_files) - set(after_files)):
        report.changes.append(
            Change(kind="file-removed", detail=f"removed {path_name}", severity="low", before=path_name)
        )
    modified = sorted(p for p in set(before_files) & set(after_files) if before_files[p] != after_files[p])
    for path_name in modified:
        report.changes.append(
            Change(kind="file-modified", detail=f"content changed: {path_name}", severity="medium", after=path_name)
        )

    # -- verdict ------------------------------------------------------------
    before_verdict = locked.get("assessment", {}).get("verdict")
    after_verdict = current["assessment"]["verdict"]
    if before_verdict and before_verdict != after_verdict:
        from skillsniff.model.result import Verdict

        worsened = Verdict(after_verdict).rank < Verdict(before_verdict).rank
        report.changes.append(
            Change(
                kind="verdict-changed",
                detail=f"verdict {before_verdict} → {after_verdict}",
                severity="critical" if worsened else "low",
                before=before_verdict,
                after=after_verdict,
            )
        )

    report.ok = not report.changes
    return report
