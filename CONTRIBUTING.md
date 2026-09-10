# Contributing

## Setup

```bash
git clone https://github.com/guthib241/SkillSniff && cd SkillSniff
python -m pip install -e ".[dev]"
pytest
```

SkillSniff must keep working with **no runtime dependencies**, so it also has to
pass with PyYAML absent. CI runs both ways.

## Before opening a pull request

```bash
pytest                              # all tests
python -m skillsniff benchmark      # no expectation failures
python -m ruff check src tests      # clean
python -m mypy                      # clean
python scripts/gen_rules_doc.py     # regenerate docs/RULES.md if rules changed
```

## Adding a rule

A rule is not finished when it fires. It is finished when it fires on the attack,
stays quiet on the lookalike, and explains itself to someone who has never read
the source.

**1. Define the metadata.**

```python
registry.define(RuleMeta(
    id="EXF005",
    title="…",
    family=Family.EXF,
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    explanation="What it looks for and how.",
    impact="What an attacker gains if this is real.",
    remediation="What the author should actually do.",
    limitations="What this rule cannot see.",   # required for high+ severity
    references=("https://…",),
))
```

`limitations` is enforced by a test for every rule at HIGH severity or above. A
security rule that documents only its strengths teaches false confidence.

**2. Implement it**, emitting through `emit()` or `_scan.emit_match()` so
enrichment and documentation-framing are automatic.

**3. Write an adversarial test** in `tests/security/test_adversarial.py` that
fails without the rule. Assert on the **rule id**, not just the verdict — a test
that only checks "something fired" passes when the wrong thing fires.

**4. Write a false-positive test** in `tests/security/test_false_positives.py`
with benign content that resembles the attack. This is not optional. Without it,
the way to make every detection test pass is to fire on everything.

**5. Add a corpus case** if the rule covers a distinct technique — and, for a new
malicious technique, a matching hard negative.

**6. Regenerate `docs/RULES.md`.**

### Choosing severity and confidence

They are independent. Severity is "how bad if true"; confidence is "how sure we
are". A dataflow observed in the AST is HIGH confidence; a phrase matched in
prose rarely is. Getting this wrong is how a tool becomes noise: a MEDIUM-
confidence guess at CRITICAL severity fails builds on hunches.

### Choosing an analysis technique

Prefer, in order:

1. **Structural** — AST, parsed manifest, archive metadata
2. **Tokenised** — quote-aware shell splitting
3. **Correlational** — capability comparison across sources
4. **Pattern** — regex, as a last resort

A regex that a comment defeats is not a rule; it is a future suppression.

## Fixing a false positive

**Never weaken a detection to make a test pass.** Find the modelling gap
instead. Every false positive fixed while building this was a real gap:
comments treated as code, documentation treated as instruction, authentication
treated as exfiltration. Each fix made the tool more accurate, not more
permissive.

When a pattern is genuinely ambiguous, prefer **downgrading** to suppressing.
`_scan.emit_match()` does this: a documentation-framed match is still recorded at
LOW severity and LOW confidence, so the evidence survives without gating a build.

## Test conventions

- Build on the clean fixture in `tests/conftest.py` so the only difference
  between the clean case and the test case is the line under examination.
- `actionable_rule_ids` (MEDIUM+) is usually the right assertion, not
  `rule_ids` — it matches what actually gates a build.
- Anything touching the scanner's own safety belongs in
  `tests/unit/test_hardening.py`.

## Documentation

Every user-facing claim needs to be true, and a limitation needs to be stated
where someone will read it — not only in `LIMITATIONS.md`.

Do not describe planned work in the present tense. `docs/ROADMAP.md` separates
IMPLEMENTED, PLANNED, EXPERIMENTAL and RESEARCH, and those categories must not
blur.

## Reporting a security issue in SkillSniff itself

See [SECURITY.md](SECURITY.md). Do not open a public issue.
