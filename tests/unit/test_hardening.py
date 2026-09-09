"""Scanner self-defence.

SkillSniff reads attacker-controlled input. These tests assert the properties
that stop that input from turning the scanner itself into the vulnerability:
paths stay inside the root, budgets bite, pathological input terminates, and a
refusal is always *recorded* rather than silent.
"""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from skillsniff.core.fs import (
    classify,
    is_safe_relative,
    looks_binary,
    read_file,
    safe_member_path,
    walk_files,
)
from skillsniff.core.limits import Budget, CoverageReason, Limits
from skillsniff.parse.archive import expand, sniff_kind


class TestPathTraversal:
    @pytest.mark.parametrize(
        "name",
        [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "/etc/passwd",
            "C:/Windows/System32",
            "a/../../b",
            "a\x00b",
            "..",
            "",
        ],
    )
    def test_hostile_member_names_are_refused(self, name):
        assert safe_member_path(name) is None

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("a/b.py", "a/b.py"),
            ("./a/b.py", "a/b.py"),
            ("a\\b.py", "a/b.py"),
            ("x.md", "x.md"),
        ],
    )
    def test_safe_member_names_are_normalised(self, name, expected):
        assert safe_member_path(name) == expected

    def test_path_inside_root_is_safe(self, tmp_path):
        (tmp_path / "a").mkdir()
        assert is_safe_relative(tmp_path, tmp_path / "a" / "b.txt")

    def test_path_outside_root_is_unsafe(self, tmp_path):
        assert not is_safe_relative(tmp_path / "a", tmp_path / "b")


class TestSymlinks:
    def test_symlink_is_skipped_and_recorded(self, tmp_path):
        target = tmp_path / "outside.txt"
        target.write_text("secret")
        root = tmp_path / "skill"
        root.mkdir()
        (root / "link.txt").symlink_to(target)

        budget = Budget()
        files = list(walk_files(root, budget))
        assert files == []
        assert any(g.reason is CoverageReason.SYMLINK_SKIPPED for g in budget.gaps)

    def test_directory_symlink_is_not_descended(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.md").write_text("secret")
        root = tmp_path / "skill"
        root.mkdir()
        (root / "link").symlink_to(outside, target_is_directory=True)

        budget = Budget()
        assert list(walk_files(root, budget)) == []
        assert any(g.reason is CoverageReason.SYMLINK_SKIPPED for g in budget.gaps)

    def test_symlink_loop_terminates(self, tmp_path):
        root = tmp_path / "skill"
        root.mkdir()
        (root / "self").symlink_to(root, target_is_directory=True)
        list(walk_files(root, Budget()))  # must terminate


class TestBudgets:
    def test_oversized_file_is_refused_and_recorded(self, tmp_path):
        target = tmp_path / "big.md"
        target.write_bytes(b"x" * 5000)
        budget = Budget(limits=Limits(max_file_bytes=1000))
        result = read_file(target, tmp_path, budget)
        assert result is not None and result.text is None
        assert any(g.reason is CoverageReason.FILE_TOO_LARGE for g in budget.gaps)

    def test_file_count_limit(self, tmp_path):
        for index in range(10):
            (tmp_path / f"f{index}.md").write_text("x")
        budget = Budget(limits=Limits(max_files=3))
        read = sum(
            1
            for path in sorted(tmp_path.glob("*.md"))
            if (result := read_file(path, tmp_path, budget)) and result.text is not None
        )
        assert read == 3
        assert any(g.reason is CoverageReason.FILE_COUNT_EXCEEDED for g in budget.gaps)

    def test_coverage_confidence_degrades(self):
        budget = Budget()
        assert budget.confidence() == "HIGH"
        budget.note_gap("x", CoverageReason.SYMLINK_SKIPPED)
        assert budget.confidence() == "MEDIUM"
        budget.note_gap("y", CoverageReason.ENCRYPTED_ARCHIVE)
        assert budget.confidence() == "LOW"


class TestArchiveHardening:
    def _zip(self, entries: dict[str, bytes | str]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
        return buffer.getvalue()

    def _scanned(self, data: bytes):
        from skillsniff.core.fs import ScannedFile

        return ScannedFile(relpath="a.zip", abspath=None, size=len(data), kind="archive", data=data)

    def test_traversal_member_is_refused(self):
        data = self._zip({"../../evil": "x", "ok.md": "fine"})
        budget = Budget()
        entries = expand(self._scanned(data), "zip", budget)
        assert [e.relpath for e in entries] == ["ok.md"]
        assert any(g.reason is CoverageReason.UNSAFE_PATH for g in budget.gaps)

    def test_decompression_bomb_is_refused(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("big.txt", b"A" * 20_000_000)
        budget = Budget()
        assert expand(self._scanned(buffer.getvalue()), "zip", budget) == []
        assert any(g.reason is CoverageReason.DECOMPRESSION_BOMB for g in budget.gaps)

    def test_depth_limit_is_enforced(self):
        payload = self._zip({"x.md": "deep"})
        for _ in range(6):
            payload = self._zip({"inner.zip": payload})
        budget = Budget(limits=Limits(max_archive_depth=2))
        expand(self._scanned(payload), "zip", budget)
        assert any(g.reason is CoverageReason.ARCHIVE_TOO_DEEP for g in budget.gaps)

    def test_encrypted_member_is_recorded(self, tmp_path):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.txt", "x")
        data = bytearray(buffer.getvalue())
        # Set the encryption flag on the local header and central directory.
        for index in range(len(data) - 4):
            if bytes(data[index : index + 4]) in (b"PK\x03\x04", b"PK\x01\x02"):
                flag = index + (6 if data[index + 3] == 4 else 8)
                data[flag] |= 0x1
        budget = Budget()
        expand(self._scanned(bytes(data)), "zip", budget)
        assert any(g.reason is CoverageReason.ENCRYPTED_ARCHIVE for g in budget.gaps)

    def test_corrupt_archive_does_not_crash(self):
        budget = Budget()
        assert expand(self._scanned(b"PK\x03\x04garbage"), "zip", budget) == []
        assert budget.gaps

    def test_archives_are_identified_by_content(self):
        data = self._zip({"a.txt": "x"})
        assert sniff_kind(data) == "zip"
        assert sniff_kind(b"just text") is None

    def test_nothing_is_written_to_disk(self, tmp_path, monkeypatch):
        """Archives are read into memory; extraction is never performed."""
        data = self._zip({"a.md": "x", "../evil": "y"})
        before = set(os.listdir(tmp_path))
        expand(self._scanned(data), "zip", Budget())
        assert set(os.listdir(tmp_path)) == before


class TestBinaryHandling:
    def test_nul_byte_means_binary(self):
        assert looks_binary(b"text\x00more")

    def test_utf8_text_is_not_binary(self):
        assert not looks_binary("héllo wörld".encode())

    def test_text_extension_with_binary_content_is_reclassified(self, tmp_path):
        target = tmp_path / "notes.md"
        target.write_bytes(b"\x00\x01\x02" * 100)
        budget = Budget()
        result = read_file(target, tmp_path, budget)
        assert result is not None and result.text is None
        assert any(g.reason is CoverageReason.BINARY for g in budget.gaps)

    def test_bytecode_is_not_excluded_by_default(self, tmp_path):
        """A .pyc is an unreviewable artifact, not build noise to be skipped."""
        (tmp_path / "x.pyc").write_bytes(b"\x00compiled")
        assert [p.name for p in walk_files(tmp_path, Budget())] == ["x.pyc"]
        assert classify("x.pyc") == "executable"


class TestRegexSafety:
    @pytest.mark.parametrize(
        "payload",
        [
            "a" * 200_000,
            ("curl " * 20_000),
            ("https://" + "a" * 50_000),
            ("(" * 5_000) + (")" * 5_000),
            "\n".join("x" * 500 for _ in range(2_000)),
        ],
    )
    def test_rules_terminate_on_pathological_input(self, payload, tmp_path, monkeypatch):
        """Every rule must complete on hostile input within the time budget."""
        import time

        from conftest import write_skill
        from skillsniff.core.config import Config
        from skillsniff.engine import scan

        path = write_skill(tmp_path, body=f"\n# S\n\n{payload}\n")
        started = time.monotonic()
        scan(path, Config())
        assert time.monotonic() - started < 30, "scan did not complete promptly"


class TestNoSubprocess:
    def test_the_scanner_never_shells_out(self):
        """A scanner that runs a subprocess against untrusted input is a liability.

        Checked with the AST rather than a text search: the rule modules contain
        the strings "subprocess" and "shell=True" as *detection patterns*, and a
        grep-based check would flag those, then get suppressed, then stop
        checking anything.
        """
        import ast
        import pathlib

        source_root = pathlib.Path(__file__).resolve().parents[2] / "src" / "skillsniff"
        forbidden_modules = {"subprocess", "pty", "ctypes", "multiprocessing"}
        forbidden_calls = {
            "os.system", "os.popen", "os.execv", "os.execve", "os.execvp",
            "os.spawnl", "os.spawnv", "os.fork", "os.posix_spawn", "eval", "exec",
        }
        offenders: list[str] = []

        for path in source_root.rglob("*.py"):
            if "bench/corpus" in path.as_posix():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".")[0] in forbidden_modules:
                            offenders.append(f"{path.name}:{node.lineno} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    if (node.module or "").split(".")[0] in forbidden_modules:
                        offenders.append(f"{path.name}:{node.lineno} imports from {node.module}")
                elif isinstance(node, ast.Call):
                    dotted = _dotted_name(node.func)
                    if dotted in forbidden_calls:
                        offenders.append(f"{path.name}:{node.lineno} calls {dotted}")

        assert not offenders, f"scanner performs process or dynamic execution: {offenders}"

    def test_the_scanner_never_extracts_archives_to_disk(self):
        """Refusing to extract removes the Zip Slip write primitive entirely."""
        import ast
        import pathlib

        source_root = pathlib.Path(__file__).resolve().parents[2] / "src" / "skillsniff"
        offenders: list[str] = []
        for path in source_root.rglob("*.py"):
            if "bench/corpus" in path.as_posix():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _dotted_name(node.func)
                    if name.endswith(("extractall", "extract")):
                        offenders.append(f"{path.name}:{node.lineno} calls {name}")
        assert not offenders, f"scanner extracts archives: {offenders}"


def _dotted_name(node) -> str:
    """Render an attribute/name chain as a dotted string."""
    import ast

    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return ""
    return ".".join(reversed(parts))
