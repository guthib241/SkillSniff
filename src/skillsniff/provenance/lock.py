"""Lockfile generation.

A lockfile records what a skill *was* at the moment someone approved it: the
hash of every file, the capabilities it exercised, the external resources it
reached, its dependencies, and the scanner version and policy state that
produced the judgement.

The point is not integrity for its own sake. It is that ``verify`` can then
answer a question no hash alone can answer — "has this skill's *behaviour*
changed since it was approved?" A file edit that adds a network call is a
different kind of event from a typo fix, and the lockfile stores enough
structure to tell them apart.

Lockfiles contain no secrets and no absolute paths, so they are safe to commit.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skillsniff import __version__
from skillsniff.core.config import Config
from skillsniff.core.errors import UsageError
from skillsniff.core.limits import Budget
from skillsniff.model.skill import load_skill

LOCK_VERSION = "1"
DEFAULT_LOCK_NAME = "skillsniff.lock.json"


def content_hash(files: list[tuple[str, str]]) -> str:
    """Hash of the whole skill: a Merkle-style digest over (path, sha256) pairs.

    Sorted so the result is independent of filesystem iteration order, and
    length-prefixed so that no rearrangement of path characters can produce a
    collision with a different file set.
    """
    digest = hashlib.sha256()
    for path, file_hash in sorted(files):
        digest.update(f"{len(path)}:{path}:{file_hash}\n".encode())
    return digest.hexdigest()


def build_lock(path: Path, config: Config | None = None) -> dict[str, Any]:
    """Analyse the skill at ``path`` and produce its lock document."""
    from skillsniff.analysis.context import build_context
    from skillsniff.engine import analyze_skill, load_rules

    config = config or Config()
    budget = Budget(limits=config.limits)
    skill = load_skill(path, budget, excludes=config.exclude, expand_archives=config.expand_archives)
    if skill is None:
        raise UsageError(f"no SKILL.md found at {path}")

    load_rules()
    result, _errors, _ = analyze_skill(skill, config, budget)
    context = build_context(skill, config, budget)

    # Only on-disk files are locked. Archive members are derived content: their
    # hashes change with the archive's, and locking both would report one edit
    # twice.
    files: list[dict[str, Any]] = [
        {"path": f.relpath, "sha256": f.sha256, "bytes": f.size}
        for f in skill.files
        if not f.container and f.sha256
    ]
    file_pairs: list[tuple[str, str]] = [
        (str(f["path"]), str(f["sha256"])) for f in files
    ]

    capabilities = sorted(
        {
            c.value
            for c in context.capabilities.actual
        }
    )

    externals = sorted(
        {
            (r.host, r.trust.value, r.pinned_to)
            for r in context.externals
            if r.host
        }
    )

    dependencies = sorted(
        {
            (d.ecosystem.value, d.name, d.version_spec, d.trust.value)
            for d in context.dependencies
            if not d.name.startswith("script:")
        }
    )

    return {
        "lock_version": LOCK_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "scanner": {"name": "skillsniff", "version": __version__},
        "skill": {
            "name": skill.name or skill.dir_name,
            "directory": skill.dir_name,
            "version": skill.version,
            "description": skill.description,
            "license": skill.license,
            "declared_tools": skill.declared_tools,
        },
        "content_hash": content_hash(file_pairs),
        "files": files,
        "capabilities": capabilities,
        "declared_capabilities": sorted(c.value for c in context.capabilities.claimed),
        "external_resources": [
            {"host": host, "trust": trust, **({"pinned_to": pin} if pin else {})}
            for host, trust, pin in externals
        ],
        "dependencies": [
            {"ecosystem": eco, "name": name, "version": spec, "trust": trust}
            for eco, name, spec, trust in dependencies
        ],
        "provenance": _provenance(path),
        "assessment": {
            "verdict": result.risk.verdict.value,
            "coverage_confidence": result.coverage.confidence,
            "findings": sorted({f.rule_id for f in result.findings}),
            "counts": result.counts(),
        },
        "policy": {
            "fail_on": config.fail_on.value,
            "select": list(config.select),
            "ignore": list(config.ignore),
        },
    }


def _provenance(path: Path) -> dict[str, Any]:
    """Best-effort repository provenance, read from .git without invoking git.

    Shelling out to git would mean running a binary against an attacker-supplied
    directory, and git honours ``.git/config`` directives from that directory.
    Reading the two files we need avoids that entirely.
    """
    provenance: dict[str, Any] = {}
    for parent in (path, *path.parents):
        git_dir = parent / ".git"
        if not git_dir.is_dir():
            continue
        head = git_dir / "HEAD"
        try:
            head_text = head.read_text(encoding="utf-8").strip()
        except OSError:
            break
        if head_text.startswith("ref:"):
            ref = head_text.split(maxsplit=1)[1]
            provenance["branch"] = ref.rsplit("/", 1)[-1]
            ref_file = git_dir / ref
            try:
                provenance["commit"] = ref_file.read_text(encoding="utf-8").strip()
            except OSError:
                packed = git_dir / "packed-refs"
                if packed.is_file():
                    for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
                        if line.endswith(f" {ref}"):
                            provenance["commit"] = line.split()[0]
                            break
        elif len(head_text) == 40:
            provenance["commit"] = head_text

        config_file = git_dir / "config"
        if config_file.is_file():
            try:
                text = config_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("url ="):
                    url = stripped.split("=", 1)[1].strip()
                    # Never record credentials embedded in a remote URL.
                    if "@" in url and "://" in url:
                        scheme, _, rest = url.partition("://")
                        url = f"{scheme}://{rest.rsplit('@', 1)[-1]}"
                    provenance["repository"] = url
                    break
        with contextlib.suppress(ValueError):
            provenance["relative_path"] = path.resolve().relative_to(parent.resolve()).as_posix()
        break
    return provenance


def write_lock(path: Path, output: Path, config: Config | None = None) -> dict[str, Any]:
    lock = build_lock(path, config)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(lock, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return lock


def read_lock(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(f"cannot read lockfile {path}: {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise UsageError(f"lockfile {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "lock_version" not in data:
        raise UsageError(f"{path} does not look like a SkillSniff lockfile")
    if str(data["lock_version"]) != LOCK_VERSION:
        raise UsageError(
            f"lockfile version {data['lock_version']} is not supported by this build "
            f"(expected {LOCK_VERSION}); regenerate it with 'skillsniff lock'"
        )
    return data
