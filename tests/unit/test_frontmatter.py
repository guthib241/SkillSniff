"""Frontmatter parsing, on both backends.

Every test that exercises parsing runs twice: once with PyYAML and once with the
dependency-free fallback. That parity is the property that matters — SkillSniff
must behave identically whether or not an optional extra is installed, because
otherwise the security result depends on the environment.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from skillsniff.parse import frontmatter as fm
from skillsniff.parse.frontmatter import IssueKind, parse


@pytest.fixture(params=["pyyaml", "fallback"])
def backend(request, monkeypatch):
    if request.param == "fallback":
        monkeypatch.setattr(fm, "HAVE_PYYAML", False)
    elif not fm.HAVE_PYYAML:
        pytest.skip("PyYAML not installed")
    return request.param


DOCUMENT = """---
name: my-skill
description: >
  Does a thing.
  Use when asked.
allowed-tools: [Read, Bash]
license: MIT
metadata:
  version: 1.0.0
  tags:
    - alpha
    - beta
compatibility:
  claude-code: ">=1.0"
---

# Body

Text here.
"""


class TestParsing:
    def test_scalars(self, backend):
        result = parse(DOCUMENT)
        assert result.data["name"] == "my-skill"
        assert result.data["license"] == "MIT"

    def test_folded_scalar(self, backend):
        result = parse(DOCUMENT)
        assert "Does a thing. Use when asked." in result.data["description"]

    def test_inline_list(self, backend):
        assert parse(DOCUMENT).data["allowed-tools"] == ["Read", "Bash"]

    def test_nested_mapping(self, backend):
        metadata = parse(DOCUMENT).data["metadata"]
        assert metadata["version"] == "1.0.0"
        assert metadata["tags"] == ["alpha", "beta"]

    def test_deeply_nested_mapping(self, backend):
        assert parse(DOCUMENT).data["compatibility"]["claude-code"] == ">=1.0"

    def test_body_and_offset(self, backend):
        result = parse(DOCUMENT)
        assert result.body.startswith("\n# Body")
        assert result.body_start_line > 1

    def test_literal_block_preserves_indentation(self, backend):
        document = "---\nname: a\ndescription: |\n  one\n    indented\n  three\n---\nbody\n"
        value = parse(document).data["description"]
        assert "one" in value and "  indented" in value and "three" in value

    def test_key_line_numbers(self, backend):
        result = parse(DOCUMENT)
        assert result.line_of("name") == 2
        assert result.line_of("allowed-tools") == 6


class TestStructuralIssues:
    def test_missing_frontmatter(self, backend):
        result = parse("# Just a heading\n")
        assert not result.present
        assert any(i.kind is IssueKind.NO_FRONTMATTER for i in result.issues)

    def test_content_before_fence(self, backend):
        result = parse("oops\n---\nname: a\n---\n")
        assert any(i.kind is IssueKind.NOT_AT_START for i in result.issues)

    def test_unclosed_fence(self, backend):
        result = parse("---\nname: a\ndescription: b\n")
        assert any(i.kind is IssueKind.UNCLOSED for i in result.issues)
        assert not result.ok

    def test_bom_is_reported_but_parsing_continues(self, backend):
        result = parse("﻿---\nname: a\ndescription: b\n---\nbody\n")
        assert any(i.kind is IssueKind.NOT_AT_START for i in result.issues)
        assert result.data["name"] == "a"

    def test_non_mapping_frontmatter(self, backend):
        result = parse("---\n- one\n- two\n---\nbody\n")
        assert any(i.kind is IssueKind.NOT_A_MAPPING for i in result.issues)


class TestHardening:
    def test_anchors_are_refused(self, backend):
        """Alias expansion is the billion-laughs vector; refusing beats bounding."""
        result = parse("---\na: &x hello\nb: *x\n---\n")
        assert any(i.kind is IssueKind.ALIASES_REFUSED for i in result.issues)
        assert result.data == {}

    def test_oversized_frontmatter_is_refused(self, backend):
        payload = "---\n" + "\n".join(f"k{i}: {'v' * 200}" for i in range(2000)) + "\n---\n"
        result = parse(payload)
        assert any(i.kind is IssueKind.TOO_LARGE for i in result.issues)

    def test_billion_laughs_does_not_expand(self, backend):
        document = "---\n" + "".join(
            f"l{i}: &l{i} [*l{i - 1}, *l{i - 1}]\n" for i in range(1, 12)
        ) + "---\n"
        result = parse("---\nl0: &l0 x\n" + document[4:])
        assert any(i.kind is IssueKind.ALIASES_REFUSED for i in result.issues)

    def test_deeply_nested_input_terminates(self, backend):
        document = "---\n" + "".join(f"{'  ' * i}k{i}:\n" for i in range(60)) + "---\n"
        parse(document)  # must not raise or hang


class TestBackendParity:
    """The two backends must agree on every document a skill can contain."""

    DOCUMENTS: ClassVar[list[str]] = [
        DOCUMENT,
        "---\nname: a\ndescription: plain\n---\nbody\n",
        "---\nname: a\ndescription: 'single quoted'\n---\n",
        '---\nname: a\ndescription: "double quoted"\n---\n',
        "---\nname: a\nallowed-tools:\n  - Read\n  - Write\n---\n",
        "---\nname: a\nmetadata:\n  nested:\n    deep: true\n---\n",
        "---\nname: a\ndescription: |\n  line one\n  line two\n---\n",
        "---\n# just a comment\nname: a\n---\n",
    ]

    @pytest.mark.parametrize("document", DOCUMENTS)
    def test_backends_agree(self, document, monkeypatch):
        if not fm.HAVE_PYYAML:
            pytest.skip("PyYAML not installed")
        with_yaml = parse(document).data
        monkeypatch.setattr(fm, "HAVE_PYYAML", False)
        without_yaml = parse(document).data
        assert with_yaml == without_yaml, (
            f"backends disagree on {document!r}: {with_yaml} != {without_yaml}"
        )
