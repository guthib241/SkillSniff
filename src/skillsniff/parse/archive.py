"""Safe archive inspection.

Archives inside a skill are a coverage problem before they are a security
problem: a scanner that does not look inside a ``.zip`` will happily call a
skill clean while the payload sits one layer down. So SkillSniff looks inside —
but everything is read into memory under a budget and *nothing is ever
extracted to disk*, which removes the entire Zip Slip write-primitive class
rather than trying to sanitise around it.

Guards implemented here:

* member names are validated before use (absolute paths, ``..``, drive letters,
  NUL bytes, backslash separators);
* declared and actual expansion are both capped, and the compression ratio is
  checked against a limit, so a 42-byte zip bomb is refused instead of expanded;
* entry count and recursion depth are bounded;
* encrypted archives are reported as an explicit coverage gap rather than
  skipped quietly;
* symlink and device members in tar files are refused outright.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass

from skillsniff.core.fs import ScannedFile, classify, looks_binary, safe_member_path
from skillsniff.core.limits import Budget, CoverageReason

#: Individual members larger than this are not read even if the archive fits.
MAX_MEMBER_BYTES = 8 * 1024 * 1024

_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"


@dataclass
class ArchiveReport:
    """What was found inside one archive."""

    container: str
    kind: str
    entries: int = 0
    extracted: int = 0
    refused: int = 0
    encrypted: bool = False
    total_uncompressed: int = 0
    total_compressed: int = 0

    @property
    def ratio(self) -> float:
        if not self.total_compressed:
            return 0.0
        return self.total_uncompressed / self.total_compressed


def sniff_kind(data: bytes) -> str | None:
    """Identify an archive by content, not by extension.

    Extension-based detection is trivially defeated by renaming ``payload.zip``
    to ``notes.md``, so the magic bytes are what decide.
    """
    if data.startswith(_ZIP_MAGIC):
        return "zip"
    if data.startswith(_GZIP_MAGIC):
        return "tar.gz"
    if data.startswith(_BZ2_MAGIC):
        return "tar.bz2"
    if data.startswith(_XZ_MAGIC):
        return "tar.xz"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    return None


def expand_all(files: list[ScannedFile], budget: Budget, depth: int = 0) -> list[ScannedFile]:
    """Expand every archive in ``files``, recursively, under the budget."""
    out: list[ScannedFile] = []
    for scanned in files:
        if scanned.data is None:
            continue
        kind = sniff_kind(scanned.data)
        if kind is None:
            continue
        out.extend(expand(scanned, kind, budget, depth=depth))
    return out


def expand(
    scanned: ScannedFile, kind: str, budget: Budget, depth: int = 0
) -> list[ScannedFile]:
    """Expand one archive into in-memory :class:`ScannedFile` entries."""
    container = scanned.display

    if depth >= budget.limits.max_archive_depth:
        budget.note_gap(
            container,
            CoverageReason.ARCHIVE_TOO_DEEP,
            f"nesting depth {depth} reaches the limit of {budget.limits.max_archive_depth}",
        )
        return []

    assert scanned.data is not None
    try:
        if kind == "zip":
            members, report = _read_zip(scanned.data, container, budget)
        else:
            members, report = _read_tar(scanned.data, container, budget, kind)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, ValueError, OSError) as exc:
        budget.note_gap(container, CoverageReason.UNPARSEABLE, f"{type(exc).__name__}: {exc}")
        return []

    budget.archives_expanded += 1

    if report.ratio and report.ratio > budget.limits.max_archive_ratio:
        budget.note_gap(
            container,
            CoverageReason.DECOMPRESSION_BOMB,
            f"expansion ratio {report.ratio:.0f}x exceeds limit "
            f"{budget.limits.max_archive_ratio}x",
        )
        return []

    results: list[ScannedFile] = []
    for name, data in members:
        results.append(_make_entry(name, data, container, depth))

    # Recurse into archives found inside this one.
    nested_inputs = [entry for entry in results if entry.data and sniff_kind(entry.data)]
    for entry in nested_inputs:
        assert entry.data is not None
        inner_kind = sniff_kind(entry.data)
        if inner_kind:
            results.extend(expand(entry, inner_kind, budget, depth=depth + 1))

    return results


def _make_entry(name: str, data: bytes, container: str, depth: int) -> ScannedFile:
    import hashlib

    kind = classify(name)
    text: str | None = None
    if kind == "text" and not looks_binary(data):
        text = data.decode("utf-8", errors="replace")
    return ScannedFile(
        relpath=name,
        abspath=None,
        size=len(data),
        kind=kind,
        text=text,
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        container=container,
        depth=depth + 1,
    )


def _read_zip(
    data: bytes, container: str, budget: Budget
) -> tuple[list[tuple[str, bytes]], ArchiveReport]:
    report = ArchiveReport(container=container, kind="zip", total_compressed=len(data))
    members: list[tuple[str, bytes]] = []

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        report.entries = len(infos)

        if len(infos) > budget.limits.max_archive_entries:
            budget.note_gap(
                container,
                CoverageReason.ARCHIVE_TOO_MANY_ENTRIES,
                f"{len(infos)} entries exceeds {budget.limits.max_archive_entries}",
            )
            infos = infos[: budget.limits.max_archive_entries]

        # Sum the *declared* sizes first: this catches a bomb before a single
        # byte is decompressed, which is the whole point of the check.
        declared = sum(i.file_size for i in infos)
        if declared and declared / max(len(data), 1) > budget.limits.max_archive_ratio:
            report.total_uncompressed = declared
            return [], report

        for info in infos:
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                report.encrypted = True
                budget.note_gap(
                    f"{container}!{info.filename}",
                    CoverageReason.ENCRYPTED_ARCHIVE,
                    "member is password-protected and cannot be inspected",
                )
                continue

            safe = safe_member_path(info.filename)
            if safe is None:
                report.refused += 1
                budget.note_gap(
                    container,
                    CoverageReason.UNSAFE_PATH,
                    f"refused archive member name {info.filename!r}",
                )
                continue

            if info.file_size > MAX_MEMBER_BYTES:
                budget.note_gap(
                    f"{container}!{safe}",
                    CoverageReason.FILE_TOO_LARGE,
                    f"{info.file_size} bytes",
                )
                continue

            try:
                with archive.open(info) as handle:
                    payload = handle.read(MAX_MEMBER_BYTES + 1)
            except (RuntimeError, zipfile.BadZipFile, OSError, EOFError) as exc:
                budget.note_gap(f"{container}!{safe}", CoverageReason.UNREADABLE, str(exc))
                continue

            if len(payload) > MAX_MEMBER_BYTES:
                budget.note_gap(
                    f"{container}!{safe}",
                    CoverageReason.DECOMPRESSION_BOMB,
                    "member expanded beyond its declared size",
                )
                continue

            report.total_uncompressed += len(payload)
            report.extracted += 1
            members.append((safe, payload))

    return members, report


def _read_tar(
    data: bytes, container: str, budget: Budget, kind: str
) -> tuple[list[tuple[str, bytes]], ArchiveReport]:
    report = ArchiveReport(container=container, kind=kind, total_compressed=len(data))
    members: list[tuple[str, bytes]] = []

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        count = 0
        for member in archive:
            count += 1
            if count > budget.limits.max_archive_entries:
                budget.note_gap(
                    container,
                    CoverageReason.ARCHIVE_TOO_MANY_ENTRIES,
                    f"more than {budget.limits.max_archive_entries} entries",
                )
                break

            # Symlinks, hardlinks and device nodes have no legitimate place in a
            # skill bundle and are the tar equivalent of a traversal primitive.
            if not member.isfile():
                if member.issym() or member.islnk() or member.isdev():
                    report.refused += 1
                    budget.note_gap(
                        container,
                        CoverageReason.UNSAFE_PATH,
                        f"refused non-regular tar member {member.name!r}",
                    )
                continue

            safe = safe_member_path(member.name)
            if safe is None:
                report.refused += 1
                budget.note_gap(
                    container,
                    CoverageReason.UNSAFE_PATH,
                    f"refused archive member name {member.name!r}",
                )
                continue

            if member.size > MAX_MEMBER_BYTES:
                budget.note_gap(f"{container}!{safe}", CoverageReason.FILE_TOO_LARGE, f"{member.size} bytes")
                continue

            if report.total_uncompressed + member.size > (
                len(data) * budget.limits.max_archive_ratio
            ):
                budget.note_gap(
                    container,
                    CoverageReason.DECOMPRESSION_BOMB,
                    "cumulative expansion exceeds the ratio limit",
                )
                break

            handle = archive.extractfile(member)
            if handle is None:
                continue
            payload = handle.read(MAX_MEMBER_BYTES + 1)
            report.total_uncompressed += len(payload)
            report.extracted += 1
            members.append((safe, payload))

        report.entries = count

    return members, report
