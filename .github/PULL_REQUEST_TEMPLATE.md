## What this changes

<!-- One or two sentences. -->

## Why

<!-- The problem, not the patch. If it fixes a false positive or false negative,
     paste the input that misbehaved. -->

## Checklist

- [ ] `pytest` passes
- [ ] `python -m skillsniff benchmark` has no expectation failures
- [ ] `python -m ruff check src tests` and `python -m mypy` are clean

### If this adds or changes a rule

- [ ] `RuleMeta` includes `limitations` (required at HIGH severity or above)
- [ ] An adversarial test asserts the **rule id**, not just the verdict
- [ ] A false-positive test covers benign content that resembles the attack
- [ ] A benchmark corpus case was added for a new technique, with a matching
      hard negative
- [ ] `docs/RULES.md` regenerated (`python scripts/gen_rules_doc.py`)

### If this changes detection behaviour

- [ ] No detection was weakened to make a test pass — the underlying modelling
      gap was fixed instead
- [ ] Benchmark precision and recall are reported below

```
<!-- paste the overall block from `python -m skillsniff benchmark` -->
```
