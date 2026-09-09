"""Safe filesystem access.

Everything here assumes the tree being walked is attacker-controlled, because
it is: a skill is downloaded content. The guarantees provided are

* no path escapes the scan root, including via symlink or ``..`` component;
* symlinks are not followed by default, and skipping one is *recorded* rather
  than silent;
* every read is size-capped and charged to the scan budget;
* binary files are detected and never fed to text rules as mojibake;
* filenames are themselves treated as untrusted content (they can carry
  Unicode evasion and traversal payloads just as file bodies can).
"""

from __future__ import annotations

import fnmatch
import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from skillsniff.core.limits import Budget, CoverageReason

#: Text-bearing suffixes we will run text rules against. Anything else is
#: recorded as a binary artifact and analysed structurally (type, size, hash)
#: rather than lexically.
TEXT_SUFFIXES = frozenset(
    {
        ".md", ".markdown", ".txt", ".rst", ".adoc",
        ".py", ".pyi", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
        ".rb", ".pl", ".php", ".lua", ".r", ".go", ".rs", ".java", ".kt",
        ".yaml", ".yml", ".json", ".jsonc", ".toml", ".ini", ".cfg", ".conf",
        ".env", ".properties", ".xml", ".html", ".htm", ".css", ".svg",
        ".sql", ".graphql", ".proto", ".dockerfile", ".makefile", ".mk",
        ".csv", ".tsv", ".lock", ".gitignore", ".npmrc", ".editorconfig",
    }
)

#: Extensionless filenames that are nevertheless text and worth reading.
TEXT_FILENAMES = frozenset(
    {
        "Dockerfile", "Makefile", "Justfile", "Procfile", "Rakefile",
        "requirements.txt", "Pipfile", "Gemfile", "LICENSE", "NOTICE",
        ".gitignore", ".npmrc", ".bashrc", ".zshrc", ".profile", ".env",
    }
)

ARCHIVE_SUFFIXES = frozenset(
    {".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz", ".xz", ".txz", ".whl", ".jar", ".egg"}
)

#: Compiled or packaged artifacts that should never appear in a skill: they are
#: unreviewable by definition.
EXECUTABLE_SUFFIXES = frozenset(
    {".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".wasm"}
)

DOCUMENT_SUFFIXES = frozenset(
    {".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".rtf", ".doc", ".xls", ".ppt"}
)

#: Paths skipped by default. Deliberately narrow.
#:
#: ``*.pyc`` and ``__pycache__`` are **not** excluded. They were, and that was a
#: hole: a skill can ship a bytecode payload with no corresponding source, and a
#: scanner that skips it will report the skill clean while never having looked.
#: Compiled artifacts are small, so there is no performance argument for
#: skipping them, and EVA002 exists precisely to flag them.
#:
#: What remains here is version-control internals and dependency trees, which
#: are large and are not the skill's own content. Skipping one is recorded as a
#: coverage gap so the report says so rather than silently omitting it.
DEFAULT_EXCLUDES = (
    ".git/*", "*/.git/*",
    "node_modules/*", "*/node_modules/*",
    ".venv/*", "*/.venv/*", "venv/*", "*/venv/*",
    ".mypy_cache/*", "*/.mypy_cache/*",
    ".ruff_cache/*", "*/.ruff_cache/*",
    ".pytest_cache/*", "*/.pytest_cache/*",
)

#: Excluded directories worth telling the user about. Skipping node_modules is
#: normal; not *saying* that it was skipped would let a clean result imply more
#: coverage than the scan actually had.
NOTABLE_EXCLUSIONS = ("node_modules", ".venv", "venv")

_NUL = b"\x00"


class FileKind(str):
    TEXT = "text"
    BINARY = "binary"
    ARCHIVE = "archive"
    EXECUTABLE = "executable"
    DOCUMENT = "document"


@dataclass
class ScannedFile:
    """One file inside a skill, already read (or explicitly not read)."""

    #: POSIX-style path relative to the skill root. Always use this in reports:
    #: absolute paths leak the scanning machine's layout into shared output.
    relpath: str
    abspath: Path | None
    size: int
    kind: str
    text: str | None = None
    data: bytes | None = field(default=None, repr=False)
    sha256: str = ""
    #: Set when this file came out of an archive rather than off disk.
    container: str = ""
    depth: int = 0
    executable_bit: bool = False

    @property
    def is_text(self) -> bool:
        return self.text is not None

    @property
    def name(self) -> str:
        return PurePosixPath(self.relpath).name

    @property
    def suffix(self) -> str:
        return PurePosixPath(self.relpath).suffix.lower()

    @property
    def display(self) -> str:
        return f"{self.container}!{self.relpath}" if self.container else self.relpath


def classify(name: str) -> str:
    """Classify a file by name alone (no I/O)."""
    pure = PurePosixPath(name)
    suffix = pure.suffix.lower()
    if suffix in ARCHIVE_SUFFIXES:
        return FileKind.ARCHIVE
    if suffix in EXECUTABLE_SUFFIXES:
        return FileKind.EXECUTABLE
    if suffix in DOCUMENT_SUFFIXES:
        return FileKind.DOCUMENT
    if suffix in TEXT_SUFFIXES or pure.name in TEXT_FILENAMES:
        return FileKind.TEXT
    return FileKind.BINARY


def looks_binary(data: bytes) -> bool:
    """Heuristic binary sniff on the first block.

    A NUL byte in the first 8 KiB is decisive; otherwise fall back to the ratio
    of bytes that are not plausible UTF-8 text.
    """
    head = data[:8192]
    if _NUL in head:
        return True
    if not head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        printable = sum(1 for b in head if 0x20 <= b < 0x7F or b in (9, 10, 13))
        return printable / len(head) < 0.75
    return False


def is_safe_relative(root: Path, candidate: Path) -> bool:
    """True when ``candidate`` resolves inside ``root``.

    Uses fully-resolved paths on both sides, which is what makes this robust to
    a symlink pointing outside the tree — comparing unresolved paths would let
    ``skill/link -> /etc`` through.
    """
    try:
        resolved_root = root.resolve(strict=False)
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    return resolved == resolved_root or resolved_root in resolved.parents


def safe_member_path(name: str) -> str | None:
    """Normalise an archive member name, or return None if it is hostile.

    Refuses absolute paths, drive letters, ``..`` traversal, and NUL bytes.
    Applied to archive entries *before* anything is extracted or joined, which
    is the only reliable place to stop a Zip Slip.
    """
    if not name or "\x00" in name:
        return None
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or (len(normalised) > 1 and normalised[1] == ":"):
        return None
    parts = [p for p in PurePosixPath(normalised).parts if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return PurePosixPath(*parts).as_posix() if parts else None


def matches_any(relpath: str, patterns: tuple[str, ...] | list[str]) -> bool:
    return any(
        fnmatch.fnmatch(relpath, pattern) or fnmatch.fnmatch(PurePosixPath(relpath).name, pattern)
        for pattern in patterns
    )


def walk_files(
    root: Path,
    budget: Budget,
    *,
    excludes: tuple[str, ...] | list[str] = DEFAULT_EXCLUDES,
) -> Iterator[Path]:
    """Yield regular files under ``root``, refusing anything unsafe.

    Directory symlinks are never descended (they are the classic way to make a
    scanner walk ``/`` or loop forever); file symlinks are skipped unless the
    budget explicitly permits following them. Both are recorded as coverage gaps.
    """
    follow = budget.limits.follow_symlinks
    root = root.resolve(strict=False)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda _e: None):
        here = Path(dirpath)
        rel_dir = _relative(here, root)

        # Prune excluded and symlinked directories in place so os.walk skips them.
        kept: list[str] = []
        for dirname in sorted(dirnames):
            child = here / dirname
            child_rel = f"{rel_dir}/{dirname}".lstrip("/")
            if matches_any(f"{child_rel}/", excludes) or matches_any(child_rel, excludes):
                if dirname in NOTABLE_EXCLUSIONS:
                    budget.note_gap(child_rel, CoverageReason.EXCLUDED, "excluded directory")
                continue
            if child.is_symlink():
                if not follow:
                    budget.note_gap(child_rel, CoverageReason.SYMLINK_SKIPPED, "directory symlink")
                    continue
                if not is_safe_relative(root, child):
                    budget.note_gap(child_rel, CoverageReason.UNSAFE_PATH, "symlink escapes root")
                    continue
            kept.append(dirname)
        dirnames[:] = kept

        for filename in sorted(filenames):
            path = here / filename
            relpath = f"{rel_dir}/{filename}".lstrip("/")
            if matches_any(relpath, excludes):
                continue
            if path.is_symlink():
                if not follow:
                    budget.note_gap(relpath, CoverageReason.SYMLINK_SKIPPED, "file symlink")
                    continue
                if not is_safe_relative(root, path):
                    budget.note_gap(relpath, CoverageReason.UNSAFE_PATH, "symlink escapes root")
                    continue
            yield path


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def read_file(path: Path, root: Path, budget: Budget) -> ScannedFile | None:
    """Read one file under the scan budget, returning None if it was refused."""
    import hashlib

    relpath = _relative(path, root)
    budget.files_discovered += 1

    try:
        info = path.lstat()
    except OSError as exc:
        budget.note_gap(relpath, CoverageReason.UNREADABLE, str(exc))
        return None

    if not stat.S_ISREG(info.st_mode):
        budget.note_gap(relpath, CoverageReason.UNREADABLE, "not a regular file")
        return None

    if not budget.allow_file(relpath, info.st_size):
        # allow_file already recorded the reason; still surface the file itself
        # so the report can say "seen but not analysed" rather than omitting it.
        return ScannedFile(
            relpath=relpath,
            abspath=path,
            size=info.st_size,
            kind=classify(relpath),
            executable_bit=bool(info.st_mode & stat.S_IXUSR),
        )

    try:
        data = path.read_bytes()
    except OSError as exc:
        budget.note_gap(relpath, CoverageReason.UNREADABLE, str(exc))
        return None

    kind = classify(relpath)
    text: str | None = None
    if kind == FileKind.TEXT and not looks_binary(data):
        text = data.decode("utf-8", errors="replace")
    elif kind == FileKind.TEXT:
        kind = FileKind.BINARY
        budget.note_gap(relpath, CoverageReason.BINARY, "text extension but binary content")

    budget.files_analyzed += 1
    return ScannedFile(
        relpath=relpath,
        abspath=path,
        size=len(data),
        kind=kind,
        text=text,
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        executable_bit=bool(info.st_mode & stat.S_IXUSR),
    )
