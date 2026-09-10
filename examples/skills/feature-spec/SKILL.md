---
name: feature-spec
description: Turns a rough feature request into a specification that is precise enough to build from, with explicit scope boundaries, edge cases, and acceptance criteria. Use when the user describes a feature they want to build, asks for a spec, PRD, or design doc, says "I want to add X", or starts implementing something whose requirements have not been pinned down.
license: MIT
metadata:
  version: 1.0.0
  category: product
  assay-grade: "A+"
---

# Feature spec

Convert a vague request into something buildable. The value is in the
questions asked before writing, not in the document's formatting.

## Rules

Non-negotiable, regardless of how well-understood the feature seems:

1. **Never invent a requirement to fill a gap.** Unknowns go in an Open
   Questions section. A confident guess presented as a requirement is how
   teams build the wrong thing quickly.
2. **Every requirement must be falsifiable.** If nobody can tell whether it
   was met, it is a wish. Rewrite it or cut it.
3. **Write the non-goals.** A spec without explicit exclusions expands until
   it is unshippable.
4. **Specify the failure paths.** The happy path is the easy quarter of the
   work; most defects live in the other three quarters.
5. **Do not begin implementing while writing the spec.** Mixing the two
   produces a document that rationalises code already written.

## Steps

1. **Restate the request as a user problem** and confirm it with the user
   before continuing. Most bad specs are faithful solutions to a
   misunderstood problem.
2. **Identify who this is for** and what they do today instead. If nobody
   currently works around the problem, question whether it exists.
3. **Interrogate the request.** Work through `references/questions.md`, which
   lists the questions that most often surface a hidden requirement. Ask the
   user the ones the request does not answer.
4. **Draw the scope boundary.** Write the goals and the non-goals together;
   each non-goal should be something a reasonable reader might have assumed
   was included.
5. **Enumerate the states and transitions**, including empty, loading,
   partial, error, offline, and concurrent-edit states.
6. **Write acceptance criteria** as observable behaviours, one per
   requirement, in the given/when/then shape.
7. **List what could go wrong**: the risks, the dependencies, and the
   assumptions that would invalidate the design if false.
8. **Verify the spec against the original request.** Re-read what the user
   first asked for and confirm every part is either specified or explicitly
   listed as a non-goal. Anything unaccounted for is a gap.

Track progress:

- [ ] Problem restated and confirmed
- [ ] Users and current workaround identified
- [ ] Interrogation questions answered or logged as open
- [ ] Goals and non-goals written
- [ ] States and transitions enumerated
- [ ] Acceptance criteria written
- [ ] Risks and assumptions listed
- [ ] Checked back against the original request

## Guardrails

Stop and ask the user rather than assuming when:

- The feature touches money, permissions, or user data deletion. Get the rule
  confirmed explicitly; do not infer it from surrounding code.
- Two stated requirements conflict. Surface the conflict; never quietly pick
  one.
- The request implies a data migration. That is a separate specification.

Do not specify implementation details unless a constraint requires them. A
spec that names the database table has skipped the part where alternatives
were compared.

Do not pad the document. Length is not thoroughness, and an unread spec
protects nobody.

## Output

```
# <Feature name>

## Problem
<the user problem, in the user's terms>

## Users
<who, and what they do today instead>

## Goals
- <observable outcome>

## Non-goals
- <explicitly excluded, with one line on why>

## Behaviour
<the states, transitions, and rules>

## Acceptance criteria
- **Given** <context> **when** <action> **then** <observable result>

## Edge cases
| Case | Expected behaviour |
| --- | --- |

## Open questions
- [ ] <question> — *blocks: <what it blocks>*

## Risks and assumptions
- <assumption, and what breaks if it is false>
```

Worked example of the difference this makes:

```
Weak:    "Users should be able to export their data."
Better:  Given a signed-in user with under 10,000 records, when they request
         an export, then a CSV download begins within 5 seconds.
         Non-goal: exports above 10,000 records (queued export, separate spec).
         Edge case: user deletes their account mid-export → export is
         cancelled and the partial file is discarded.
```

## Caveats

- **The interrogation is the product.** A spec written without asking the
  user anything mostly restates the request in more words.
- **A common pitfall is writing acceptance criteria that restate the
  implementation** ("the endpoint returns 200"). Criteria describe what the
  user observes, not what the code does.
- **Open questions get skipped under deadline pressure.** Mark what each one
  blocks so the cost of leaving it open is visible.
- If the feature cannot be specified without a decision the user has not
  made, the correct output is a shorter document plus that decision, not a
  longer document that hides it.
