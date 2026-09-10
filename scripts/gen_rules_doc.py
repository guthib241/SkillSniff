#!/usr/bin/env python3
"""Generate docs/RULES.md from the rule registry.

The catalogue is derived, never hand-maintained, so it cannot drift from the
rules that actually run. CI regenerates it and fails if the checked-in copy
differs.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from skillsniff import __version__  # noqa: E402
from skillsniff.engine import load_rules  # noqa: E402
from skillsniff.rules.base import registry  # noqa: E402

HEADER = f"""# Rule catalogue

{{count}} rules in {{families}} families, generated from the registry by
`scripts/gen_rules_doc.py` for SkillSniff {__version__}. Do not edit by hand.

`skillsniff explain <RULE>` prints any entry below, including its limitations.

Severity answers "how bad if true". Confidence answers "how sure the detection
is". They are separate so a high-severity, low-confidence finding can surface for
review without failing a build.

The `SPEC` and `QUA` families sit outside the security taxonomy and never
contribute to the security verdict.

"""


def main() -> int:
    load_rules()
    metas = registry.all_meta()
    families = sorted({m.family for m in metas}, key=lambda f: f.value)

    lines: list[str] = [HEADER.format(count=len(metas), families=len(families))]

    lines.append("## Index\n")
    lines.append("| Family | Rules | Scope |")
    lines.append("| --- | --- | --- |")
    for family in families:
        count = len(registry.by_family(family))
        scope = "security" if family.is_security else "not security"
        lines.append(f"| [`{family.value}`](#{family.value.lower()}) {family.label} | {count} | {scope} |")
    lines.append("")

    for family in families:
        lines.append(f"## {family.value}\n")
        lines.append(f"**{family.label}**")
        if not family.is_security:
            lines.append(
                "\n> Findings in this family are reported separately and never affect the "
                "security verdict."
            )
        lines.append("")

        for meta in registry.by_family(family):
            lines.append(f"### `{meta.id}` — {meta.title}\n")
            flags = [f"**{meta.severity.value}**", f"{meta.confidence.value} confidence"]
            if meta.experimental:
                flags.append("**experimental**")
            lines.append(" · ".join(flags) + "\n")
            lines.append(f"**Detects.** {meta.explanation}\n")
            lines.append(f"**Why it matters.** {meta.impact}\n")
            lines.append(f"**Fix.** {meta.remediation}\n")
            if meta.limitations:
                lines.append(f"**Cannot detect.** {meta.limitations}\n")
            if meta.taxonomy:
                lines.append(f"**Taxonomy.** {', '.join(f'`{t}`' for t in meta.taxonomy)}\n")
            if meta.references:
                refs = ", ".join(f"[{i + 1}]({r})" for i, r in enumerate(meta.references))
                lines.append(f"**References.** {refs}\n")

    (ROOT / "docs" / "RULES.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"wrote docs/RULES.md ({len(metas)} rules, {len(families)} families)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
