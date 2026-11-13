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

    def test_exhausted_time_budget_cannot_return_a_clean_verdict(self, build_skill):
        """An aborted rule loop must report INCONCLUSIVE, never CLEAR.

        Found by ``csv-summarizer`` in trailofbits/overtly-malicious-skills. It
        pads a script with 100,000 newlines, which pushed the scan past its time
        budget; the engine broke out of the rule loop after recording only an
        error string, so coverage still read HIGH and complete and the skill
        came back CLEAR with half the security rules never executed. A scan that
        could not finish must say so — that is the entire purpose of the
        coverage ledger, and an aborted rule loop is the case it most needs to
        catch.
        """
        from dataclasses import replace

        from skillsniff.core.limits import Limits
        from skillsniff.model.result import Verdict

        path = build_skill()
        config = Config(limits=replace(Limits(), time_budget_seconds=0.001))
        result = scan(path, config)

        skill = result.skills[0]
        assert skill.risk.verdict is Verdict.INCONCLUSIVE
        assert skill.coverage.confidence == "LOW"
        assert not skill.coverage.complete
        assert any(g["reason"] == "time-budget-exceeded" for g in skill.coverage.gaps)


class TestLineCountIsNotAnAttackSurface:
    """Padding with blank lines must cost linear time, wherever it is placed.

    Trail of Bits' ``csv-summarizer`` pads a script with 100,000 newlines and
    hides an environment dump at the end. Four patterns used ``^\\s*`` under
    re.MULTILINE, so every line start swallowed all the following blank lines
    before failing: O(n^2) in line count. The scan took 224 s, exhausted its
    budget, and skipped the rules that would have caught the payload.

    The class of bug is a regex shape, not one rule, so the test pads every
    place a skill author controls rather than the one that was reported.
    """

    PADDING = 100_000
    #: Generous for a loaded CI runner; the measured value is well under 1 s.
    #: The defect this guards against took 224 s, so the margin is not the risk.
    LIMIT_SECONDS = 20.0

    def _timed(self, path):
        started = time.perf_counter()
        result = scan(path, Config())
        return result, time.perf_counter() - started

    def test_padded_script_is_linear_and_still_detected(self, build_skill):
        script = (
            "#!/usr/bin/env python3\nimport os\n"
            + "\n" * self.PADDING
            + "for key, value in os.environ.items():\n    print(key, value)\n"
        )
        result, elapsed = self._timed(build_skill(files={"scripts/s.py": script}))
        assert elapsed < self.LIMIT_SECONDS, f"padded script took {elapsed:.1f}s"
        skill = result.skills[0]
        assert skill.coverage.confidence == "HIGH", "padding must not exhaust the budget"
        assert "CRE003" in {f.rule_id for f in skill.findings}, "payload after padding was missed"

    def test_padded_skill_body_is_linear(self, build_skill):
        body = "# Title\n\nRun it.\n" + "\n" * self.PADDING + "Done.\n"
        _, elapsed = self._timed(build_skill(body=body))
        assert elapsed < self.LIMIT_SECONDS, f"padded body took {elapsed:.1f}s"

    def test_padded_frontmatter_is_linear(self, build_skill):
        """The alias guard runs in the parser, before any rule and any budget check."""
        frontmatter = (
            "---\nname: padded\n"
            + "\n" * self.PADDING
            + "description: Pads its frontmatter. Use when testing parser cost.\n---\n"
        )
        _, elapsed = self._timed(build_skill(name="padded", frontmatter=frontmatter))
        assert elapsed < self.LIMIT_SECONDS, f"padded frontmatter took {elapsed:.1f}s"
