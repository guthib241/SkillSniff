"""SARIF 2.1.0 output.

SARIF is how findings reach GitHub code scanning, and the format rewards being
precise about two things this tool cares about: rule metadata travels with the
run (so every finding is explainable in the UI), and severity is expressed both
as a SARIF ``level`` and as a numeric ``security-severity``, which is what
GitHub uses to sort and to gate.

Confidence is carried in the finding's properties rather than folded into
severity, so a low-confidence critical stays visibly low-confidence.
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from skillsniff import __version__
from skillsniff.model.finding import Confidence, Finding, Severity
from skillsniff.model.result import ScanResult
from skillsniff.rules.base import registry

SARIF_VERSION = "2.1.0"
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

#: SARIF defines only error/warning/note/none, so the five severities collapse.
#: security-severity preserves the ordering GitHub sorts on.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _rule_descriptor(rule_id: str) -> dict[str, Any] | None:
    meta = registry.meta(rule_id)
    if meta is None:
        return None

    full = meta.explanation
    if meta.impact:
        full += f"\n\n**Impact.** {meta.impact}"
    if meta.remediation:
        full += f"\n\n**Remediation.** {meta.remediation}"
    if meta.limitations:
        full += f"\n\n**Limitations.** {meta.limitations}"

    descriptor: dict[str, Any] = {
        "id": meta.id,
        "name": _pascal(meta.id, meta.title),
        "shortDescription": {"text": meta.title},
        "fullDescription": {"text": meta.explanation},
        "help": {"text": full, "markdown": full},
        "defaultConfiguration": {"level": _LEVEL[meta.severity]},
        "properties": {
            "tags": [meta.family.value, meta.family.label, *meta.taxonomy],
            "security-severity": _SECURITY_SEVERITY[meta.severity],
            "family": meta.family.value,
            "confidence": meta.confidence.value,
            "experimental": meta.experimental,
        },
    }
    if meta.references:
        descriptor["helpUri"] = meta.references[0]
    return descriptor


def _pascal(rule_id: str, title: str) -> str:
    words = "".join(part.capitalize() for part in title.replace("/", " ").split() if part.isalnum())
    return f"{rule_id}{words}"[:120] or rule_id


def _location(finding: Finding, skill_path: str) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for evidence in finding.evidence[:5]:
        # An evidence path can point inside an archive ("bundle.zip!inner.md").
        # SARIF has no notion of that, so the physical location is the archive
        # and the logical path is carried in a property.
        physical, _, inner = evidence.path.partition("!")
        region: dict[str, Any] = {}
        if evidence.line:
            region["startLine"] = max(1, evidence.line)
            if evidence.end_line and evidence.end_line >= evidence.line:
                region["endLine"] = evidence.end_line
        if evidence.column:
            region["startColumn"] = max(1, evidence.column)
        if evidence.excerpt:
            region["snippet"] = {"text": evidence.excerpt[:400]}

        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(skill_path, physical)},
                **({"region": region} if region else {}),
            }
        }
        properties = {
            k: v
            for k, v in (
                ("nestedPath", inner),
                ("decodeChain", evidence.decode_chain),
                ("note", evidence.note),
            )
            if v
        }
        if properties:
            location["properties"] = properties
        locations.append(location)

    return locations or [
        {"physicalLocation": {"artifactLocation": {"uri": _uri(skill_path, "SKILL.md")}}}
    ]


def _uri(skill_path: str, relpath: str) -> str:
    prefix = skill_path.strip("/").split("/")[-1] if skill_path else ""
    return f"{prefix}/{relpath}" if prefix and not relpath.startswith(prefix) else relpath


def build(result: ScanResult) -> dict[str, Any]:
    seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for skill in result.skills:
        for finding in skill.findings:
            if finding.rule_id not in seen:
                descriptor = _rule_descriptor(finding.rule_id)
                if descriptor:
                    seen[finding.rule_id] = descriptor

            entry: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": _LEVEL[finding.severity],
                "message": {"text": f"{finding.title}: {finding.message}" if finding.message else finding.title},
                "locations": _location(finding, skill.path),
                "properties": {
                    "skill": finding.skill,
                    "family": finding.family,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "advisory": finding.advisory,
                    "security-severity": _SECURITY_SEVERITY[finding.severity],
                },
            }
            if finding.confidence is Confidence.LOW:
                entry["properties"]["suppressionCandidate"] = True
            if finding.related:
                entry["properties"]["relatedRules"] = finding.related
            if finding.rule_id in seen:
                entry["ruleIndex"] = list(seen).index(finding.rule_id)
            results.append(entry)

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillSniff",
                        "version": __version__,
                        "informationUri": "https://github.com/guthib241/SkillSniff",
                        "semanticVersion": __version__,
                        "rules": list(seen.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "workingDirectory": {"uri": result.scanned_path},
                        **({"toolExecutionNotifications": [
                            {"level": "error", "message": {"text": error}} for error in result.errors[:20]
                        ]} if result.errors else {}),
                    }
                ],
                "properties": {
                    "verdict": result.verdict.value,
                    "skillsScanned": len(result.skills),
                    "coverage": {
                        s.name: s.coverage.confidence for s in result.skills
                    },
                },
            }
        ],
    }


def render(result: ScanResult, stream: TextIO | None = None, *, indent: int | None = 2) -> None:
    json.dump(build(result), stream or sys.stdout, indent=indent)
    print(file=stream or sys.stdout)
