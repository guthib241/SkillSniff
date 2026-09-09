"""Performance characteristics.

Thresholds are deliberately generous — several times the measured value on
ordinary hardware — because this suite must not flake on a loaded CI runner. It
is a guard against an order-of-magnitude regression, not a benchmark.

It exists because one already happened: a correctness fix bypassed the memoised
text projection, so `normalize()` ran once per rule over the same megabyte. The
scan still produced the right answer, so only a timing test would have caught it.
"""

from __future__ import annotations

import base64
import io
import statistics
import time
import zipfile
from pathlib import Path

import pytest

from skillsniff.core.config import Config
from skillsniff.engine import scan

pytestmark = pytest.mark.slow

CORPUS = Path(__file__).resolve().parents[2] / "src" / "skillsniff" / "bench" / "corpus"


def _time(path: Path, runs: int = 3) -> float:
    """Median wall-clock milliseconds for a scan."""
    timings = []
    for _ in range(runs):
        started = time.perf_counter()
        scan(path, Config())
        timings.append((time.perf_counter() - started) * 1000)
    return statistics.median(timings)


class TestScanSpeed:
    def test_small_skill_is_fast(self, build_skill):
        assert _time(build_skill()) < 500

    def test_many_reference_files(self, build_skill):
        files = {f"references/r{i}.md": "# Ref\n" + ("word " * 400) for i in range(20)}
        assert _time(build_skill(files=files)) < 5_000

    def test_one_very_long_line(self, build_skill):
        """The padding/minification shape, and an attacker's natural choice."""
        path = build_skill(files={"references/x.md": "a" * 1_000_000})
        assert _time(path) < 15_000

    def test_many_encoded_regions(self, build_skill):
        blobs = "\n".join(
            base64.b64encode(f"payload number {i} with text".encode()).decode()
            for i in range(100)
        )
        assert _time(build_skill(files={"references/e.md": blobs})) < 5_000

    def test_archive_with_many_entries(self, build_skill):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for index in range(200):
                archive.writestr(f"e{index}.md", "# entry\n" + ("word " * 200))
        path = build_skill(files={"assets/b.zip": buffer.getvalue()})
        assert _time(path) < 10_000

    @pytest.mark.skipif(not CORPUS.is_dir(), reason="corpus not present")
    def test_corpus_throughput(self):
        result = scan(CORPUS, Config())
        started = time.perf_counter()
        scan(CORPUS, Config())
        per_skill = ((time.perf_counter() - started) * 1000) / len(result.skills)
        assert per_skill < 200, f"{per_skill:.1f} ms per skill"


class TestProjectionsAreMemoised:
    def test_normalize_runs_once_per_file(self, build_skill, monkeypatch):
        """The regression this module exists for.

        Counted rather than timed, so the assertion is exact and cannot flake.
        """
        import skillsniff.core.text as text_module

        calls: list[int] = []
        original = text_module.normalize

        def counting(value: str) -> str:
            calls.append(len(value))
            return original(value)

        monkeypatch.setattr(text_module, "normalize", counting)
        monkeypatch.setattr("skillsniff.rules._scan.normalize", counting, raising=False)

        path = build_skill(files={"references/big.md": "word " * 20_000})
        scan(path, Config())

        # Two text files (SKILL.md and the reference), each normalised at most
        # a small constant number of times regardless of how many rules run.
        big = [n for n in calls if n > 50_000]
        assert len(big) <= 2, f"large file normalised {len(big)} times; memoisation is broken"


class TestResourceBudgets:
    def test_oversized_file_does_not_dominate(self, build_skill):
        """A file above the limit is refused quickly, not read and then dropped."""
        from dataclasses import replace

        from skillsniff.core.limits import Limits

        path = build_skill(files={"references/huge.md": "x" * 2_000_000})
        config = Config(limits=replace(Limits(), max_file_bytes=1000))
        started = time.perf_counter()
        result = scan(path, config)
        elapsed = (time.perf_counter() - started) * 1000
        assert elapsed < 2_000
        assert result.skills[0].coverage.gaps
