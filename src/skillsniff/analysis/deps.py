"""Dependency manifest analysis.

A skill's dependencies are code that will run with the agent's privileges, so
they are part of its capability surface even though the author did not write
them. This module reads the manifest formats a skill realistically bundles and
extracts each dependency with enough structure to judge whether it is pinned.

Unpinned is the finding that matters. ``requests>=2`` means the code that runs
next month is not the code that was reviewed today, and for a security-relevant
artifact that is a supply-chain hole regardless of how trustworthy the package
is now.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum

from skillsniff.analysis.external import TrustLevel
from skillsniff.model.finding import Evidence


class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    RUBYGEMS = "rubygems"
    CARGO = "cargo"
    GO = "go"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    name: str
    version_spec: str
    ecosystem: Ecosystem
    trust: TrustLevel
    evidence: Evidence
    reasons: list[str] = field(default_factory=list)
    is_direct_url: bool = False
    is_git: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version_spec,
            "ecosystem": self.ecosystem.value,
            "trust": self.trust.value,
            "reasons": list(self.reasons),
            "evidence": self.evidence.as_dict(),
        }


_EXACT_PIN = re.compile(r"^==\s*\d[\w.!+-]*$")
_HASH_PIN = re.compile(r"--hash=sha\d+:")
_NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.]+)?$")
_GIT_URL = re.compile(r"^(?:git\+)?(?:https?|ssh|git)://|^git@")
_SHA_RE = re.compile(r"\b[0-9a-f]{40}\b")


def _classify_python_spec(spec: str, raw_line: str) -> tuple[TrustLevel, list[str]]:
    reasons: list[str] = []
    if _HASH_PIN.search(raw_line):
        return TrustLevel.PINNED, ["pinned by artifact hash"]
    if not spec:
        return TrustLevel.MUTABLE, ["no version constraint: resolves to the latest release"]
    if _EXACT_PIN.match(spec.strip()):
        reasons.append("pinned to an exact version, but not to an artifact hash")
        return TrustLevel.VERSIONED, reasons
    if any(op in spec for op in (">=", ">", "~=", "^", "*", "!=")):
        return TrustLevel.MUTABLE, [f"version range {spec!r} admits future releases"]
    return TrustLevel.UNKNOWN, [f"unrecognised version specifier {spec!r}"]


def parse_requirements(text: str, path: str) -> list[Dependency]:
    """Parse a pip requirements file."""
    out: list[Dependency] = []
    for offset, raw in enumerate(text.splitlines()):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            if line.startswith(("-e", "--editable")):
                target = line.split(maxsplit=1)[-1]
                out.append(
                    Dependency(
                        name=target,
                        version_spec="",
                        ecosystem=Ecosystem.PYPI,
                        trust=TrustLevel.MUTABLE,
                        evidence=Evidence(path=path, line=offset + 1, excerpt=raw.strip()[:160]),
                        reasons=["editable install from a local or remote path"],
                        is_direct_url=True,
                    )
                )
            continue

        if _GIT_URL.match(line) or "@ git+" in line or line.startswith("git+"):
            pinned = bool(_SHA_RE.search(line))
            out.append(
                Dependency(
                    name=line.split("#egg=")[-1] if "#egg=" in line else line,
                    version_spec="",
                    ecosystem=Ecosystem.PYPI,
                    trust=TrustLevel.PINNED if pinned else TrustLevel.MUTABLE,
                    evidence=Evidence(path=path, line=offset + 1, excerpt=raw.strip()[:160]),
                    reasons=(
                        ["VCS dependency pinned to a commit"]
                        if pinned
                        else ["VCS dependency tracks a branch; the code can change without notice"]
                    ),
                    is_git=True,
                    is_direct_url=True,
                )
            )
            continue

        match = re.match(r"^([A-Za-z0-9][\w.\-]*)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if not match:
            continue
        name, _extras, spec = match.group(1), match.group(2), match.group(3).strip()
        spec = spec.split(";", 1)[0].strip()
        trust, reasons = _classify_python_spec(spec, raw)
        out.append(
            Dependency(
                name=name,
                version_spec=spec,
                ecosystem=Ecosystem.PYPI,
                trust=trust,
                evidence=Evidence(path=path, line=offset + 1, excerpt=raw.strip()[:160]),
                reasons=reasons,
            )
        )
    return out


def parse_package_json(text: str, path: str) -> list[Dependency]:
    """Parse the dependency blocks of a package.json."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[Dependency] = []
    for block in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        entries = data.get(block)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            if not isinstance(spec, str):
                continue
            line = _line_of_key(text, name)
            trust, reasons = _classify_npm_spec(spec)
            out.append(
                Dependency(
                    name=str(name),
                    version_spec=spec,
                    ecosystem=Ecosystem.NPM,
                    trust=trust,
                    evidence=Evidence(path=path, line=line, excerpt=f'"{name}": "{spec}"'),
                    reasons=reasons,
                    is_git=spec.startswith(("git", "github:")) or "://" in spec,
                )
            )

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            command = scripts.get(hook)
            if isinstance(command, str) and command.strip():
                out.append(
                    Dependency(
                        name=f"script:{hook}",
                        version_spec=command[:120],
                        ecosystem=Ecosystem.NPM,
                        trust=TrustLevel.SUSPICIOUS,
                        evidence=Evidence(
                            path=path, line=_line_of_key(text, hook), excerpt=command[:160]
                        ),
                        reasons=[
                            f"npm {hook} hook runs automatically at install time, "
                            "before any code is reviewed or executed deliberately"
                        ],
                    )
                )
    return out


def _classify_npm_spec(spec: str) -> tuple[TrustLevel, list[str]]:
    value = spec.strip()
    if value in ("*", "latest", "") or value.startswith("^") or value.startswith("~"):
        return TrustLevel.MUTABLE, [f"npm range {value!r} resolves to newer releases automatically"]
    if value.startswith(("git", "github:", "http")):
        return (
            (TrustLevel.PINNED, ["VCS dependency pinned to a commit"])
            if _SHA_RE.search(value)
            else (TrustLevel.MUTABLE, ["VCS dependency without a commit pin"])
        )
    if value.startswith("file:"):
        return TrustLevel.UNKNOWN, ["local path dependency; contents are outside this artifact"]
    if _NPM_EXACT.match(value):
        return TrustLevel.VERSIONED, ["exact version, but npm has no artifact-hash pin here"]
    return TrustLevel.MUTABLE, [f"unpinned specifier {value!r}"]


def _line_of_key(text: str, key: str) -> int:
    match = re.search(rf'"{re.escape(key)}"\s*:', text)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def parse_pyproject(text: str, path: str) -> list[Dependency]:
    """Extract PEP 621 dependencies without requiring a TOML parser round-trip."""
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python < 3.11
        return []
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []

    specs: list[str] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        raw = project.get("dependencies")
        if isinstance(raw, list):
            specs.extend(str(item) for item in raw)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    specs.extend(str(item) for item in group)

    out: list[Dependency] = []
    for spec in specs:
        match = re.match(r"^([A-Za-z0-9][\w.\-]*)\s*(\[[^\]]*\])?\s*(.*)$", spec.strip())
        if not match:
            continue
        name, constraint = match.group(1), match.group(3).strip()
        trust, reasons = _classify_python_spec(constraint, spec)
        out.append(
            Dependency(
                name=name,
                version_spec=constraint,
                ecosystem=Ecosystem.PYPI,
                trust=trust,
                evidence=Evidence(path=path, line=_line_of_text(text, spec), excerpt=spec[:160]),
                reasons=reasons,
            )
        )
    return out


def _line_of_text(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index != -1 else 1


MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements,
    "requirements-dev.txt": parse_requirements,
    "requirements_dev.txt": parse_requirements,
    "package.json": parse_package_json,
    "pyproject.toml": parse_pyproject,
}


def parse_manifest(name: str, text: str, path: str) -> list[Dependency]:
    """Dispatch on manifest filename; returns [] for anything unrecognised."""
    parser = MANIFEST_PARSERS.get(name)
    if parser is None and name.startswith("requirements") and name.endswith(".txt"):
        parser = parse_requirements
    return parser(text, path) if parser else []
