# Reference skills

Four skills that pass SkillSniff's default gate, kept here for two reasons:
they show what a well-formed skill looks like, and the repository's self-scan
runs against them, so the tool is continuously applied to something other than
its own test fixtures.

| Skill | What it does |
| --- | --- |
| [`threat-model-review`](threat-model-review) | Threat-models a change and reports attack paths with severity and mitigations |
| [`accessible-ui-review`](accessible-ui-review) | Finds accessibility defects and returns the markup that fixes them |
| [`feature-spec`](feature-spec) | Turns a vague request into a spec precise enough to build from |
| [`skill-authoring`](skill-authoring) | Writes and repairs skills |

```bash
skillsniff scan ./examples/skills
skillsniff inspect ./examples/skills/threat-model-review
```

## Why these are useful beyond being examples

These were written for SkillSniff's predecessor, against a different rule set,
before any of the current rules existed. That makes them the only content in
this repository that was not authored alongside the rules that judge it — and
scanning them immediately found a real false positive:

`INJ003` (concealment) fired on `feature-spec`'s line

> A spec written **without asking** the user anything mostly restates the request.

which is advice *advocating* asking the user. The rule was conflating two
different things: concealment is about hiding what was done, while failing to
ask is about permission. `without asking` was removed from the concealment
pattern, and instruction-level permission bypass moved to `PRV001` behind a
pattern that requires an actual imperative. Both directions have regression
tests.

That is one false positive from four skills, which is not a statistic. It is
worth recording because it is the kind of finding a self-authored corpus
structurally cannot produce, and it is the argument for the source-disjoint
evaluation named in [`docs/ROADMAP.md`](../../docs/ROADMAP.md).

## Provenance

Carried over from this repository's predecessor and MIT-licensed under the same
terms as the rest of the project. They are examples, not a curated marketplace:
a passing scan means no issues were detected by the enabled checks, which is not
a claim that the procedures they encode are correct.
