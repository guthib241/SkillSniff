"""Obfuscation and scanner-evasion rules (OBS, EVA families).

These rules do not ask "is this content malicious". They ask "is this content
arranged so that a human reviewer and the model read different things", which is
a property that has no legitimate use in a skill and is measurable without
understanding intent.

That framing is what makes them high-signal: benign skills do not hide their
text, do not pad their files with megabytes of whitespace, and do not ship
instructions encoded in Unicode tag characters.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator

from skillsniff.analysis.context import AnalysisContext
from skillsniff.core.text import UnicodeThreat, decode_tag_characters
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity
from skillsniff.rules import _scan
from skillsniff.rules.base import Family, RuleMeta, emit, registry

TROJAN_SOURCE = "https://trojansource.codes/"

#: Instruction-shaped content. Used to decide whether a *decoded* region is
#: merely encoded data or an actual hidden payload.
PAYLOAD_SIGNALS = re.compile(
    r"\b(?:curl|wget|bash|sh\b|eval|exec|subprocess|os\.system|import\s+os|"
    r"require\(|child_process|powershell|Invoke-Expression|/bin/sh|"
    r"ignore\s+(?:all\s+)?previous|api[_-]?key|token|password|secret|"
    r"ssh|\.aws|credential|http[s]?://)",
    re.IGNORECASE,
)

registry.define_all(
    [
        RuleMeta(
            id="OBS001",
            title="Invisible characters in skill content",
            family=Family.OBS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "Zero-width spaces, joiners, soft hyphens and similar formatting characters "
                "render as nothing to a human but are part of the token stream the model reads. "
                "They are used both to hide instructions and to break up keywords so that a "
                "literal-matching scanner misses them."
            ),
            impact=(
                "A reviewer approves text that differs from what the agent acts on. Every other "
                "control in the review process is built on the assumption those are the same."
            ),
            remediation=(
                "Strip the characters. If a specific one is genuinely required (a soft hyphen in "
                "typeset prose, a ZWJ in an emoji sequence), keep it and suppress this rule for "
                "that path rather than repository-wide."
            ),
            limitations=(
                "Legitimate uses exist in non-Latin scripts and emoji sequences, so this rule "
                "reports position and character rather than asserting malice."
            ),
            references=(TROJAN_SOURCE,),
        ),
        RuleMeta(
            id="OBS002",
            title="Bidirectional control characters",
            family=Family.OBS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "Bidi overrides and isolates (U+202A–U+202E, U+2066–U+2069) reorder how text is "
                "displayed without changing its logical order. The rendered line a reviewer "
                "reads can be arbitrarily different from the line that is executed."
            ),
            limitations=(
                "Reports the presence of bidi control characters. It does not render the text "
                "both ways to show what a reviewer would have seen versus what executes."
            ),
            impact=(
                "The 'Trojan Source' class of attack: a command can be displayed as a comment, "
                "or a condition displayed inverted, with the real behaviour invisible in review."
            ),
            remediation="Remove the control characters entirely.",
            references=(TROJAN_SOURCE,),
        ),
        RuleMeta(
            id="OBS003",
            title="Instructions hidden in Unicode tag characters",
            family=Family.OBS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "The Unicode Tag block (U+E0000–U+E007F) mirrors ASCII, renders as nothing in "
                "essentially every client, and survives copy-paste. This rule decodes any tag "
                "run back to the ASCII it carries."
            ),
            limitations=(
                "Decodes the Unicode Tag block only. Other invisible channels are covered by "
                "OBS001, and a channel this tool does not know about would not be reported at "
                "all."
            ),
            impact=(
                "A complete instruction set can be carried invisibly inside otherwise innocuous "
                "text. Nothing in a normal review workflow surfaces it."
            ),
            remediation="Remove every code point in the U+E0000–U+E007F range.",
            references=(TROJAN_SOURCE,),
        ),
        RuleMeta(
            id="OBS004",
            title="Homoglyph or mixed-script evasion",
            family=Family.OBS,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A word mixes scripts and contains a character that looks like an ASCII letter — "
                "Cyrillic 'с' for Latin 'c', for example. This defeats literal keyword matching "
                "while reading identically to a human."
            ),
            impact=(
                "Keyword-based controls (scanners, allowlists, review filters) miss the term while "
                "the model still resolves the meaning from context."
            ),
            remediation="Replace the non-ASCII lookalikes with their ASCII equivalents.",
            limitations=(
                "Uses a curated homoglyph table covering the Cyrillic, Greek, Armenian and "
                "fullwidth lookalikes seen in practice, not the complete UTS #39 confusables "
                "set. Genuine multilingual prose is not flagged: the rule requires script "
                "mixing *within a single word*."
            ),
            references=("https://www.unicode.org/reports/tr39/",),
        ),
        RuleMeta(
            id="OBS005",
            title="Encoded payload with executable or credential content",
            family=Family.OBS,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            explanation=(
                "A base64, hex, percent- or escape-encoded region decodes to content containing "
                "shell commands, network fetches, credential references, or injection phrasing. "
                "Decoding is recursive, so a payload wrapped twice is still resolved."
            ),
            impact=(
                "Encoding is how a payload is carried past both human review and pattern-based "
                "scanning. Content that has to be decoded before it makes sense was hidden on purpose."
            ),
            remediation=(
                "Inline the content in plain text so it can be reviewed. If the data is "
                "legitimately binary, document what it is and why it must be embedded."
            ),
            limitations=(
                "Only reports decoded regions whose content looks executable or credential-"
                "related; an encoded payload of pure natural language is reported by OBS006 at "
                "lower severity. Encryption, rather than encoding, is not recoverable and is "
                "reported as a coverage gap instead."
            ),
            references=(TROJAN_SOURCE,),
        ),
        RuleMeta(
            id="OBS006",
            title="Large encoded region",
            family=Family.OBS,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A substantial encoded blob is present whose decoded content is not obviously "
                "executable. Reported for visibility rather than as a defect."
            ),
            impact=(
                "Encoded content cannot be reviewed by reading the file, so it is a blind spot "
                "in any review that does not decode it."
            ),
            remediation="Inline the content in plain text, or document what the blob is.",
            limitations="Embedded images and test fixtures legitimately look like this.",
        ),
        RuleMeta(
            id="EVA001",
            title="Suspicious padding or truncation",
            family=Family.EVA,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            explanation=(
                "A file contains a long run of whitespace or repeated filler, or a single line "
                "far longer than the rest of the document. Both are used to push content past "
                "the window a reviewer reads or a tool truncates."
            ),
            impact=(
                "Content positioned after the padding is present in the artifact and read by the "
                "model, but is effectively invisible in a diff view or a truncated preview."
            ),
            remediation="Remove the padding and keep lines to a readable length.",
            limitations="Minified assets and generated data files trip this legitimately.",
        ),
        RuleMeta(
            id="EVA002",
            title="Executable or bytecode artifact bundled with the skill",
            family=Family.EVA,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "The skill bundles a compiled binary, shared library, or Python bytecode file. "
                "This tool does not disassemble them, and neither does a human reviewer."
            ),
            limitations=(
                "SkillSniff does not disassemble binaries, so it reports that the artifact "
                "exists and is unanalysed. It cannot tell a benign compiled helper from a "
                "malicious one."
            ),
            impact=(
                "A compiled artifact is unreviewable by inspection. Whatever it does is outside "
                "the coverage of this scan and of any code review of the repository."
            ),
            remediation=(
                "Ship source, not binaries. If a binary is genuinely required, publish its build "
                "provenance and hash so it can be reproduced independently."
            ),
            references=(),
        ),
        RuleMeta(
            id="EVA003",
            title="File content does not match its extension",
            family=Family.EVA,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            explanation=(
                "A file's magic bytes identify it as an archive or binary while its extension "
                "claims something else — 'notes.md' that is actually a ZIP, for example."
            ),
            limitations=(
                "Identifies archive and common binary formats by magic bytes. A format "
                "without a recognised signature, or a file that is genuinely what its "
                "extension claims, is not reported."
            ),
            impact=(
                "Extension-based tooling, including many scanners and review UIs, will treat the "
                "file as text and never inspect what it really contains."
            ),
            remediation="Give the file its correct extension, or remove it.",
        ),
        RuleMeta(
            id="EVA004",
            title="Hidden file or directory in the skill bundle",
            family=Family.EVA,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            explanation=(
                "The skill bundles dot-prefixed files beyond the conventional set. These are "
                "hidden from directory listings and from casual review."
            ),
            impact="Content that a reviewer is unlikely to open, shipped inside the artifact.",
            remediation="Move required configuration to a visible path, or delete the file.",
            limitations="Common dotfiles (.gitignore, .editorconfig) are excluded.",
        ),
    ]
)


@registry.implement("OBS001", "OBS002", "OBS004")
def check_unicode(context: AnalysisContext) -> Iterator[Finding]:
    """Report Unicode threat classes, grouped per file to avoid a wall of findings."""
    mapping = {
        UnicodeThreat.ZERO_WIDTH: "OBS001",
        UnicodeThreat.VARIATION_SELECTOR: "OBS001",
        UnicodeThreat.PRIVATE_USE: "OBS001",
        UnicodeThreat.UNUSUAL_SPACE: "OBS001",
        UnicodeThreat.CONTROL: "OBS001",
        UnicodeThreat.BIDI_CONTROL: "OBS002",
        UnicodeThreat.CONFUSABLE: "OBS004",
    }

    for file in context.text_files():
        view = file.view
        if view is None:
            continue
        grouped: dict[str, list] = {}
        for unicode_finding in view.unicode_findings:
            rule_id = mapping.get(unicode_finding.threat)
            if rule_id:
                grouped.setdefault(rule_id, []).append(unicode_finding)

        for rule_id, items in grouped.items():
            counts = Counter(f"{i.display} ({i.char_name})" for i in items)
            summary = ", ".join(f"{name}×{n}" if n > 1 else name for name, n in counts.most_common(4))
            evidence = [
                Evidence(
                    path=file.path,
                    line=item.line,
                    excerpt=item.context[:140],
                    note=f"{item.display} {item.char_name}",
                )
                for item in items[:5]
            ]
            yield emit(
                rule_id,
                context.name,
                message=f"{file.path}: {len(items)} occurrence(s) — {summary}",
                evidence=evidence,
            )


@registry.implement("OBS003")
def check_tag_characters(context: AnalysisContext) -> Iterator[Finding]:
    for file in context.text_files():
        view = file.view
        if view is None:
            continue
        hidden = decode_tag_characters(view.raw)
        if not hidden:
            continue
        line = next(
            (f.line for f in view.unicode_findings if f.threat is UnicodeThreat.TAG_CHARACTER), 1
        )
        yield emit(
            "OBS003",
            context.name,
            message=(
                f"{file.path}: {len(hidden)} Unicode tag characters decode to "
                f"{hidden[:100]!r}"
            ),
            evidence=[
                Evidence(
                    path=file.path,
                    line=line,
                    excerpt=hidden[:140],
                    decode_chain="unicode-tag",
                    note="invisible in every standard renderer",
                )
            ],
        )


#: Below this many decoded characters a region is too small to be a payload.
_MIN_REPORTABLE_DECODE = 16


@registry.implement("OBS005", "OBS006")
def check_encoded_payloads(context: AnalysisContext) -> Iterator[Finding]:
    for file in context.text_files():
        view = file.view
        if view is None:
            continue
        # Nested regions inherit the origin line of their outermost wrapper, so
        # deduplicating by line alone would report the harmless outer blob and
        # discard the payload inside it. Group by line and keep the region that
        # actually carries a signal.
        by_line: dict[int, list] = {}
        for region in view.decoded:
            if region.encoding.value == "tag-unicode":
                continue  # covered by OBS003
            if len(region.text) < _MIN_REPORTABLE_DECODE:
                continue
            by_line.setdefault(region.origin_line, []).append(region)

        for regions in by_line.values():
            region = next(
                (r for r in regions if PAYLOAD_SIGNALS.search(r.text)),
                max(regions, key=lambda r: len(r.text)),
            )
            signal = PAYLOAD_SIGNALS.search(region.text)
            evidence = [
                Evidence(
                    path=file.path,
                    line=region.origin_line,
                    excerpt=region.text[:160].replace("\n", " "),
                    decode_chain=region.chain,
                    note=f"{len(region.text)} decoded characters",
                )
            ]
            if signal:
                yield emit(
                    "OBS005",
                    context.name,
                    message=(
                        f"{file.path}: {region.chain} region decodes to content containing "
                        f"{signal.group(0)!r}"
                    ),
                    evidence=evidence,
                )
            elif len(region.text) >= 64:
                yield emit(
                    "OBS006",
                    context.name,
                    message=f"{file.path}: {len(region.text)}-character {region.chain} region",
                    evidence=evidence,
                )


_PADDING_RE = re.compile(r"(?:[ \t]{200,}|\n{40,}|(.)\1{500,})")
_MAX_REASONABLE_LINE = 5000


@registry.implement("EVA001")
def check_padding(context: AnalysisContext) -> Iterator[Finding]:
    for file in context.text_files():
        view = file.view
        if view is None:
            continue
        raw = view.raw
        match = _PADDING_RE.search(raw[: _scan.MAX_SCAN_BYTES])
        if match:
            yield emit(
                "EVA001",
                context.name,
                message=(
                    f"{file.path}: {len(match.group(0))} characters of padding at line "
                    f"{raw.count(chr(10), 0, match.start()) + 1}"
                ),
                evidence=[
                    file.evidence(
                        line=raw.count("\n", 0, match.start()) + 1,
                        excerpt=f"{len(match.group(0))} repeated characters",
                    )
                ],
            )
            continue

        lines = raw.splitlines()
        if len(lines) < 3:
            continue
        longest = max(range(len(lines)), key=lambda i: len(lines[i]))
        length = len(lines[longest])
        median = sorted(len(line) for line in lines)[len(lines) // 2]
        if length > _MAX_REASONABLE_LINE and length > max(median * 40, 400):
            yield emit(
                "EVA001",
                context.name,
                message=(
                    f"{file.path}: line {longest + 1} is {length} characters against a median "
                    f"of {median}"
                ),
                evidence=[
                    file.evidence(line=longest + 1, excerpt=lines[longest][:120]),
                ],
            )


@registry.implement("EVA002")
def check_executables(context: AnalysisContext) -> Iterator[Finding]:
    from skillsniff.core.fs import FileKind

    for file in context.files:
        if file.scanned.kind == FileKind.EXECUTABLE:
            yield emit(
                "EVA002",
                context.name,
                message=f"{file.path}: {file.scanned.size} bytes of compiled or bytecode content",
                evidence=[
                    Evidence(
                        path=file.path,
                        excerpt=f"sha256:{file.scanned.sha256[:16]}…",
                        note="not analysed: this scanner does not disassemble binaries",
                    )
                ],
            )


@registry.implement("EVA003")
def check_extension_mismatch(context: AnalysisContext) -> Iterator[Finding]:
    from skillsniff.core.fs import FileKind
    from skillsniff.parse.archive import sniff_kind

    for file in context.files:
        data = file.scanned.data
        if not data:
            continue
        actual = sniff_kind(data)
        if actual is None:
            continue
        if file.scanned.kind != FileKind.ARCHIVE:
            yield emit(
                "EVA003",
                context.name,
                message=(
                    f"{file.path}: extension suggests {file.scanned.kind}, but the content is "
                    f"a {actual} archive"
                ),
                evidence=[
                    Evidence(
                        path=file.path,
                        excerpt=f"magic bytes identify {actual}",
                        note="extension-based tooling will not inspect this file's real contents",
                    )
                ],
            )


_EXPECTED_DOTFILES = frozenset(
    {
        ".gitignore", ".gitattributes", ".editorconfig", ".gitkeep", ".keep",
        ".dockerignore", ".npmignore", ".prettierrc", ".eslintrc", ".DS_Store",
    }
)


@registry.implement("EVA004")
def check_hidden_files(context: AnalysisContext) -> Iterator[Finding]:
    hidden: list[str] = []
    for file in context.files:
        parts = file.scanned.relpath.split("/")
        name = parts[-1]
        if any(p.startswith(".") for p in parts[:-1]) or (
            name.startswith(".") and name not in _EXPECTED_DOTFILES
        ):
            hidden.append(file.path)

    if hidden:
        yield emit(
            "EVA004",
            context.name,
            message=f"{len(hidden)} hidden path(s): {', '.join(sorted(hidden)[:5])}",
            evidence=[Evidence(path=path) for path in sorted(hidden)[:5]],
        )
