"""SkillSniff applied to itself and to its own corpus.

The self-scan is not decoration. A scanner whose own repository trips its rules
is either wrong about the rules or wrong about itself, and either way somebody
needs to look.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skillsniff.bench.runner import default_corpus_path, load_cases, run_benchmark
from skillsniff.core.config import Config
from skillsniff.engine import load_rules
from skillsniff.model.finding import Severity
from skillsniff.rules.base import Family, registry

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestRegistryIntegrity:
    def test_every_defined_rule_is_implemented(self):
        load_rules()
        assert registry.unimplemented() == []

    def test_every_rule_has_complete_metadata(self):
        load_rules()
        for meta in registry.all_meta():
            assert meta.title, f"{meta.id} has no title"
            assert len(meta.explanation) > 40, f"{meta.id} explanation is too thin"
            assert len(meta.impact) > 20, f"{meta.id} does not say why it matters"
            assert len(meta.remediation) > 20, f"{meta.id} does not say how to fix it"

    def test_security_rules_document_their_limits(self):
        """A security rule that documents only its strengths teaches false confidence."""
        load_rules()
        missing = [
            m.id
            for m in registry.all_meta()
            if m.family.is_security and m.severity.rank <= Severity.HIGH.rank and not m.limitations
        ]
        assert not missing, f"high-severity rules with no documented limitations: {missing}"

    def test_rule_ids_match_their_family(self):
        load_rules()
        for meta in registry.all_meta():
            assert meta.id.startswith(meta.family.value)

    def test_no_duplicate_rule_ids(self):
        load_rules()
        ids = [m.id for m in registry.all_meta()]
        assert len(ids) == len(set(ids))

    def test_quality_and_spec_are_not_security_families(self):
        assert not Family.QUA.is_security
        assert not Family.SPEC.is_security
        assert Family.EXF.is_security


class TestCorpusIntegrity:
    def test_corpus_exists(self):
        assert default_corpus_path().is_dir()

    def test_every_case_is_well_formed(self):
        for case in load_cases(default_corpus_path()):
            assert case.label in ("malicious", "benign")
            assert (case.path / "SKILL.md").is_file(), f"{case.name} has no SKILL.md"
            if case.is_malicious:
                assert case.expect_rules, f"{case.name} declares no expected rule"

    def test_corpus_has_hard_negatives(self):
        """Without benign lookalikes, firing on everything would score perfectly."""
        cases = load_cases(default_corpus_path())
        hard = [c for c in cases if c.category.startswith("hard-negative")]
        assert len(hard) >= 8, "the corpus needs benign cases that resemble attacks"

    def test_corpus_is_balanced_enough_to_be_meaningful(self):
        cases = load_cases(default_corpus_path())
        benign = [c for c in cases if not c.is_malicious]
        assert len(benign) >= 10


@pytest.mark.slow
class TestBenchmark:
    def test_no_expectation_failures(self):
        report = run_benchmark(default_corpus_path())
        assert not report.expectation_failures, [
            r.as_dict() for r in report.expectation_failures
        ]

    def test_no_false_negatives(self):
        """A missed malicious case is the failure that matters most."""
        report = run_benchmark(default_corpus_path())
        assert report.overall.false_negative == 0

    def test_no_false_positives(self):
        report = run_benchmark(default_corpus_path())
        assert report.overall.false_positive == 0

    def test_scan_is_fast(self):
        report = run_benchmark(default_corpus_path())
        assert report.median_ms < 500, f"median scan took {report.median_ms:.0f} ms"


class TestReferenceSkills:
    """The skills in examples/ must stay clean under the strictest settings.

    These were written for this project's predecessor, against a different rule
    set, before any current rule existed — the only content here not authored
    alongside the rules that judge it. Scanning them found one real false
    positive (INJ003 on "without asking"), which is the argument for the
    source-disjoint evaluation in docs/ROADMAP.md.
    """

    EXAMPLES = REPO_ROOT / "examples" / "skills"

    def test_reference_skills_are_present(self):
        """A self-scan with nothing to scan passes vacuously."""
        skills = list(self.EXAMPLES.glob("*/SKILL.md"))
        assert len(skills) >= 4, f"expected reference skills under {self.EXAMPLES}"

    def test_reference_skills_are_clean_under_strict(self):
        """Every rule enabled, failing on any severity."""
        from skillsniff.core.config import Config as _Config
        from skillsniff.engine import scan

        result = scan(self.EXAMPLES, _Config(strict=True, fail_on=Severity.INFO))
        offenders = [
            (f.skill, f.rule_id, f.severity.value, f.message[:80])
            for f in result.all_findings
        ]
        assert not offenders, f"reference skills are no longer clean: {offenders}"

    def test_reference_skills_have_full_coverage(self):
        """A clean result on partially-analysed content would prove nothing."""
        from skillsniff.core.config import Config as _Config
        from skillsniff.engine import scan

        for skill in scan(self.EXAMPLES, _Config()).skills:
            assert skill.coverage.confidence == "HIGH", (
                f"{skill.name}: coverage {skill.coverage.confidence}, "
                f"gaps {skill.coverage.gaps}"
            )


@pytest.mark.slow
class TestSelfScan:
    def test_repository_has_no_actionable_findings(self):
        """SkillSniff's own tree, excluding the deliberately-malicious corpus."""
        from skillsniff.core.config import Config as _Config
        from skillsniff.core.limits import Budget
        from skillsniff.model.skill import discover_skills

        config = _Config(
            exclude=(*Config().exclude, "bench/corpus/*", "*/bench/corpus/*", "tests/*", "*/tests/*")
        )
        skills = discover_skills(REPO_ROOT, Budget(limits=config.limits), excludes=config.exclude)
        # The repository ships no skills of its own outside the corpus; if that
        # changes, this test starts scanning them, which is the intent.
        for skill in skills:
            assert "corpus" not in str(skill.root)

    #: Paths permitted to contain credential-shaped strings, because detecting
    #: them is what those files are *for*. Kept explicit and narrow: an
    #: allowlist that grows silently is how a real key eventually lands in a
    #: repository. Every value behind these paths is a synthetic fixture that
    #: has never been valid at any provider.
    SECRET_FIXTURE_PATHS = (
        "src/skillsniff/bench/corpus/",
        "tests/security/",
    )

    def test_secret_allowlist_stays_minimal(self):
        """The allowlist itself is reviewed, so it cannot quietly expand."""
        assert len(self.SECRET_FIXTURE_PATHS) <= 3

    def test_no_secrets_are_committed(self):
        """The scanner's own credential rule, applied to the scanner."""
        from skillsniff.rules.secrets import HARDCODED_SECRET, _plausible_secret

        offenders: list[str] = []
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file() or ".git/" in path.as_posix():
                continue
            relative = path.relative_to(REPO_ROOT).as_posix()
            if any(relative.startswith(prefix) for prefix in self.SECRET_FIXTURE_PATHS):
                continue
            if path.suffix not in (".py", ".toml", ".md", ".yml", ".yaml", ".json", ".sh", ".txt"):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for match in HARDCODED_SECRET.finditer(text):
                if _plausible_secret(match.group(0)):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {match.group(0)[:12]}…")
        assert not offenders, f"credential-shaped strings committed: {offenders}"

    def test_no_large_files_are_committed(self):
        limit = 2 * 1024 * 1024
        oversized = [
            f"{p.relative_to(REPO_ROOT)} ({p.stat().st_size} bytes)"
            for p in REPO_ROOT.rglob("*")
            if p.is_file() and ".git/" not in p.as_posix() and p.stat().st_size > limit
        ]
        assert not oversized, f"unexpectedly large files: {oversized}"
