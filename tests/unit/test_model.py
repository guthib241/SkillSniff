"""Finding model, risk assessment, and configuration."""

from __future__ import annotations

import pytest

from skillsniff.core.config import Config, from_mapping
from skillsniff.core.errors import ConfigError
from skillsniff.model.finding import (
    Confidence,
    Evidence,
    Finding,
    Severity,
    deduplicate,
    sort_findings,
)
from skillsniff.model.result import Coverage, Verdict, assess


def make(rule_id: str, severity: Severity, family: str, confidence=Confidence.HIGH, line=1) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        confidence=confidence,
        skill="s",
        family=family,
        evidence=[Evidence(path="SKILL.md", line=line)],
    )


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.INFO.rank

    def test_parse_is_case_insensitive(self):
        assert Severity.parse("  CRITICAL ") is Severity.CRITICAL

    def test_parse_rejects_unknown(self):
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("catastrophic")

    def test_at_or_above(self):
        assert Severity.at_or_above(Severity.HIGH) == {Severity.CRITICAL, Severity.HIGH}


class TestFindingOrdering:
    def test_sorted_by_severity_then_confidence(self):
        findings = [
            make("A", Severity.LOW, "EXF"),
            make("B", Severity.CRITICAL, "EXF", Confidence.LOW),
            make("C", Severity.CRITICAL, "EXF", Confidence.HIGH),
        ]
        assert [f.rule_id for f in sort_findings(findings)] == ["C", "B", "A"]

    def test_deduplicate_same_rule_same_location(self):
        findings = [make("A", Severity.HIGH, "EXF"), make("A", Severity.HIGH, "EXF")]
        assert len(deduplicate(findings)) == 1

    def test_deduplicate_keeps_distinct_locations(self):
        findings = [
            make("A", Severity.HIGH, "EXF", line=1),
            make("A", Severity.HIGH, "EXF", line=9),
        ]
        assert len(deduplicate(findings)) == 2

    def test_deduplicate_prefers_decoded_evidence(self):
        plain = make("A", Severity.HIGH, "EXF")
        decoded = make("A", Severity.HIGH, "EXF")
        decoded.evidence = [Evidence(path="SKILL.md", line=1, decode_chain="base64")]
        kept = deduplicate([plain, decoded])[0]
        assert kept.primary is not None and kept.primary.decode_chain == "base64"


class TestRiskAssessment:
    COMPLETE = Coverage(files_analyzed=5, files_discovered=5, confidence="HIGH")

    def test_critical_security_blocks(self):
        assert assess([make("EXF001", Severity.CRITICAL, "EXF")], self.COMPLETE).verdict is Verdict.BLOCK

    def test_quality_never_affects_the_verdict(self):
        """The defect the previous single-score design had."""
        quality = [make(f"QUA{i:03d}", Severity.MEDIUM, "QUA") for i in range(6)]
        assert assess(quality, self.COMPLETE).verdict is Verdict.CLEAR

    def test_quality_cannot_offset_security(self):
        findings = [make("EXF001", Severity.CRITICAL, "EXF")]
        findings += [make(f"QUA{i:03d}", Severity.INFO, "QUA") for i in range(20)]
        assert assess(findings, self.COMPLETE).verdict is Verdict.BLOCK

    def test_specification_findings_are_not_security(self):
        spec = [make("SPEC001", Severity.HIGH, "SPEC")]
        assessment = assess(spec, self.COMPLETE)
        assert assessment.verdict is Verdict.CLEAR
        assert assessment.dimensions["specification"].band.value == "high"

    def test_low_coverage_forbids_a_clean_verdict(self):
        coverage = Coverage(files_analyzed=1, files_discovered=10, confidence="LOW")
        assert assess([], coverage).verdict is Verdict.INCONCLUSIVE

    def test_critical_outranks_low_coverage(self):
        coverage = Coverage(files_analyzed=1, files_discovered=10, confidence="LOW")
        assert assess([make("EXF001", Severity.CRITICAL, "EXF")], coverage).verdict is Verdict.BLOCK

    def test_low_confidence_critical_does_not_block(self):
        finding = make("EXF001", Severity.CRITICAL, "EXF", Confidence.LOW)
        assert assess([finding], self.COMPLETE).verdict is not Verdict.BLOCK

    def test_critical_in_supply_chain_blocks(self):
        """A Zip Slip is critical whichever family it lives in."""
        assert assess([make("ARC001", Severity.CRITICAL, "ARC")], self.COMPLETE).verdict is Verdict.BLOCK

    def test_high_severity_requires_review(self):
        assert assess([make("EXE003", Severity.HIGH, "EXE")], self.COMPLETE).verdict is Verdict.REVIEW

    def test_clean_scan_is_clear(self):
        assessment = assess([], self.COMPLETE)
        assert assessment.verdict is Verdict.CLEAR
        assert "no security" in " ".join(assessment.rationale)

    def test_verdict_wording_never_claims_safety(self):
        for verdict in Verdict:
            assert "safe" not in verdict.summary.lower()


class TestConfig:
    def test_defaults(self):
        config = Config()
        assert config.fail_on is Severity.HIGH
        assert config.is_enabled("EXF001")

    def test_ignore_by_family_prefix(self):
        config = from_mapping({"ignore": ["QUA"]})
        assert not config.is_enabled("QUA001")
        assert config.is_enabled("EXF001")

    def test_select_restricts(self):
        config = from_mapping({"select": ["EXF"]})
        assert config.is_enabled("EXF001")
        assert not config.is_enabled("QUA001")

    def test_ignore_wins_over_select(self):
        config = from_mapping({"select": ["EXF"], "ignore": ["EXF002"]})
        assert config.is_enabled("EXF001")
        assert not config.is_enabled("EXF002")

    def test_unknown_key_is_rejected(self):
        with pytest.raises(ConfigError, match="unknown configuration key"):
            from_mapping({"failon": "high"})

    def test_unknown_limit_is_rejected(self):
        with pytest.raises(ConfigError, match="unknown limit"):
            from_mapping({"limits": {"max_flies": 3}})

    def test_limits_are_merged_not_replaced(self):
        config = from_mapping({"limits": {"max_files": 7}})
        assert config.limits.max_files == 7
        assert config.limits.max_archive_depth == Config().limits.max_archive_depth

    def test_discovery_walks_upwards(self, tmp_path):
        from skillsniff.core.config import discover

        (tmp_path / ".skillsniff.toml").write_text('[skillsniff]\nfail_on = "critical"\n')
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        assert discover(nested).fail_on is Severity.CRITICAL
