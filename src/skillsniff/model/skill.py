"""The skill model.

A skill is not one SKILL.md file. It is a directory of artifacts — instructions,
scripts, reference documents, dependency manifests, and sometimes archives —
every one of which reaches the agent. Modelling only the Markdown is how a
scanner misses the payload in ``scripts/setup.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillsniff.core.fs import (
    DEFAULT_EXCLUDES,
    FileKind,
    ScannedFile,
    read_file,
    walk_files,
)
from skillsniff.core.limits import Budget
from skillsniff.core.text import TextView
from skillsniff.parse.frontmatter import Frontmatter, parse as parse_frontmatter

SKILL_FILENAMES = ("SKILL.md", "skill.md", "Skill.md")


@dataclass
class Skill:
    """A loaded skill and every artifact bundled with it."""

    root: Path
    dir_name: str
    entry_relpath: str = "SKILL.md"
    frontmatter: Frontmatter = field(default_factory=Frontmatter)
    raw: str = ""
    files: list[ScannedFile] = field(default_factory=list)
    #: Files recovered from inside archives, keyed the same way as ``files``.
    nested: list[ScannedFile] = field(default_factory=list)
    _views: dict[str, TextView] = field(default_factory=dict, repr=False)

    # -- frontmatter accessors ---------------------------------------------

    @property
    def name(self) -> str:
        value = self.frontmatter.get("name")
        return value if isinstance(value, str) else ""

    @property
    def description(self) -> str:
        value = self.frontmatter.get("description")
        return value if isinstance(value, str) else ""

    @property
    def body(self) -> str:
        return self.frontmatter.body

    @property
    def declared_tools(self) -> list[str]:
        """Tools the skill declares, from ``allowed-tools``.

        Accepts both the list form and the comma-separated string form that
        appears in the wild, because rejecting the string form would make the
        scanner report "no tools declared" on a skill that declared several.
        """
        value = self.frontmatter.get("allowed-tools")
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        if isinstance(value, str):
            return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
        return []

    @property
    def metadata(self) -> dict[str, Any]:
        value = self.frontmatter.get("metadata")
        return value if isinstance(value, dict) else {}

    @property
    def version(self) -> str:
        value = self.metadata.get("version")
        return str(value) if value is not None else ""

    @property
    def license(self) -> str:
        value = self.frontmatter.get("license")
        return value if isinstance(value, str) else ""

    # -- file accessors -----------------------------------------------------

    @property
    def all_files(self) -> list[ScannedFile]:
        return [*self.files, *self.nested]

    @property
    def text_files(self) -> list[ScannedFile]:
        return [f for f in self.all_files if f.is_text]

    def view(self, scanned: ScannedFile) -> TextView | None:
        """Memoised :class:`TextView` for a file, or None if it is not text."""
        if scanned.text is None:
            return None
        key = scanned.display
        view = self._views.get(key)
        if view is None:
            view = TextView(raw=scanned.text, path=key)
            self._views[key] = view
        return view

    @property
    def entry_file(self) -> ScannedFile | None:
        return next((f for f in self.files if f.relpath == self.entry_relpath), None)

    def has_dir(self, name: str) -> bool:
        return (self.root / name).is_dir()

    def line_of(self, needle: str) -> int | None:
        index = self.raw.find(needle)
        return None if index == -1 else self.raw.count("\n", 0, index) + 1

    @property
    def body_words(self) -> int:
        return len(self.body.split())

    @property
    def body_lines(self) -> int:
        return len(self.body.splitlines())

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.all_files)


def find_entry(directory: Path) -> Path | None:
    for candidate in SKILL_FILENAMES:
        path = directory / candidate
        if path.is_file():
            return path
    return None


def load_skill(
    directory: Path,
    budget: Budget | None = None,
    *,
    excludes: tuple[str, ...] | list[str] = DEFAULT_EXCLUDES,
    expand_archives: bool = True,
) -> Skill | None:
    """Load the skill rooted at ``directory``, or None if there is no SKILL.md."""
    entry = find_entry(directory)
    if entry is None:
        return None

    budget = budget or Budget()
    root = directory.resolve(strict=False)

    files: list[ScannedFile] = []
    for path in walk_files(root, budget, excludes=excludes):
        scanned = read_file(path, root, budget)
        if scanned is not None:
            files.append(scanned)

    entry_rel = entry.name
    raw = next((f.text or "" for f in files if f.relpath == entry_rel), "")
    if not raw:
        # The entry file was refused by the budget (huge, or binary). Read the
        # head directly so parsing still has something, and let the coverage
        # ledger carry the caveat.
        try:
            raw = entry.read_text(encoding="utf-8", errors="replace")[: budget.limits.max_regex_input]
        except OSError:
            raw = ""

    skill = Skill(
        root=root,
        dir_name=root.name,
        entry_relpath=entry_rel,
        frontmatter=parse_frontmatter(raw),
        raw=raw,
        files=files,
    )

    if expand_archives:
        from skillsniff.parse.archive import expand_all

        skill.nested = expand_all(files, budget)

    return skill


def discover_skills(
    root: Path,
    budget: Budget | None = None,
    *,
    excludes: tuple[str, ...] | list[str] = DEFAULT_EXCLUDES,
    expand_archives: bool = True,
) -> list[Skill]:
    """Find every skill at or under ``root``.

    A directory containing SKILL.md is a skill and is *not* descended into: a
    reference file that happens to be named SKILL.md inside another skill is
    part of that skill, not a sibling of it.
    """
    budget = budget or Budget()
    root = root.resolve(strict=False)

    if find_entry(root) is not None:
        skill = load_skill(root, budget, excludes=excludes, expand_archives=expand_archives)
        return [skill] if skill else []

    directories: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_dir() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        from skillsniff.core.fs import matches_any

        if matches_any(rel, excludes) or matches_any(f"{rel}/", excludes):
            continue
        if any(str(path).startswith(f"{parent}/") for parent in map(str, directories)):
            continue
        if find_entry(path) is not None:
            directories.append(path)

    skills: list[Skill] = []
    for directory in directories:
        skill = load_skill(directory, budget, excludes=excludes, expand_archives=expand_archives)
        if skill is not None:
            skills.append(skill)
    return skills
