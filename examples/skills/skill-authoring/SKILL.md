---
name: skill-authoring
description: Writes and repairs Agent Skills (SKILL.md files) that pass spec validation, avoid the documented skill smells, and actually trigger when they should. Use when the user wants to create a skill, package a workflow as a reusable skill, fix a skill that never activates, improve a skill's description, or asks about SKILL.md, agent skills, or the Agent Skills format.
license: MIT
metadata:
  version: 1.0.0
  category: meta
  assay-grade: "A+"
---

# Skill authoring

Write skills that load, trigger, and hold up. In a study of 238 popular
published skills, over 99% carried at least one documented defect, averaging
10.5 each. Nearly all of those defects are avoidable by construction.

## Rules

Non-negotiable. A skill that violates any of these is broken regardless of
how good its prose is:

1. **The directory name must equal the `name` field.** Loaders resolve skills
   by directory. A mismatch means the skill is silently never found. Verify
   this before anything else.
2. **Only these frontmatter keys are permitted:** `name`, `description`,
   `license`, `allowed-tools`, `metadata`, `compatibility`. Anything else
   fails validation. Custom fields go under `metadata`.
3. **The description must state when to use the skill, not only what it
   does.** This is the single highest-value line in the file and the most
   common reason a skill never triggers.
4. **Never put XML-style tags in the description.** They are injected into the
   agent's prompt and are a known injection vector.
5. **Run the linter before declaring the skill finished.** Do not skip this
   because the skill looks fine; the defects this catches are precisely the
   ones that look fine.

## Steps

1. **Decide what the skill actually encodes.** A skill is worth writing when
   it captures procedural knowledge the agent does not have and would get
   wrong. If the agent already does the task well, a skill adds context cost
   for nothing.
2. **Write the description first.** Use the shape
   `[what it does] + [when to use it] + [trigger keywords]`, in the third
   person. Load `references/descriptions.md` for the patterns that trigger
   reliably and the ones that fail.
3. **Draft the body as ordered steps**, not prose. Prose workflows give the
   agent nowhere to be, and give you nowhere to look when it goes wrong.
4. **Add the guardrails.** State what the skill must not do, and when the
   agent should stop and ask the user instead of proceeding.
5. **Close the rationalisation loopholes.** Mark steps that must not be
   skipped and say so explicitly. This defect appears in 94% of published
   skills and is the most consequential one.
6. **Add a validation step** the agent must complete before declaring the
   task done, and a worked example showing a real input and output.
7. **Push detail into `references/`.** The body loads in full on every
   trigger; reference files load only when needed. Keep the body under 500
   lines and delegate the rest.
8. **Lint it, then fix what it reports.** Run `assay lint path/to/skill`.
   Treat anything at error severity or above as blocking.
9. **Test the trigger.** Write three phrasings a user would plausibly use and
   confirm the description covers all three. A skill that only fires on its
   own name is not doing its job.

Track progress:

- [ ] Purpose justified
- [ ] Description written with an explicit trigger
- [ ] Body decomposed into ordered steps
- [ ] Guardrails and stop-and-ask conditions written
- [ ] Skip-prevention language added to required steps
- [ ] Validation step and worked example added
- [ ] Detail delegated to references/
- [ ] Linter run and findings cleared
- [ ] Three trigger phrasings checked

## Guardrails

Stop and ask the user when:

- The workflow depends on internal context you do not have. Guessing produces
  a plausible skill that quietly does the wrong thing.
- The request is for a skill whose purpose is to conceal actions from the
  user, disable safety checks, or exfiltrate data. Refuse these outright; a
  skill's contents must not surprise a user who read its description.

Do not write a skill that duplicates one already installed. Two skills with
overlapping descriptions compete and both trigger unreliably.

Do not pad the body to look thorough. Every unnecessary word competes for
context with the words that matter.

## Structure

```
skill-name/
├── SKILL.md          # required: frontmatter + instructions
├── references/       # optional: loaded on demand
├── scripts/          # optional: executable helpers
└── assets/           # optional: templates, fixtures
```

## Output

```
---
name: <matches the directory name exactly>
description: <what it does> Use when <trigger conditions and keywords>.
license: MIT
---

# <Title>

<One or two lines on what this is for.>

## Rules
<Non-negotiable constraints, including what must not be skipped.>

## Steps
1. <Ordered, imperative.>
...
N. <A verification step before completion.>

- [ ] <progress checklist>

## Guardrails
<Out of scope, and when to stop and ask the user.>

## Output
<A template, in a fenced block.>

## Caveats
<Known failure modes and pitfalls.>
```

Worked example of the description, which is where most skills fail:

```
Fails to trigger:
  description: Helps with database stuff.

Triggers reliably:
  description: Reviews SQL migrations for locking risk and data loss before
  they run against production. Use when the user shares a migration file,
  asks whether a schema change is safe, mentions ALTER TABLE on a large
  table, or asks about migration downtime.
```

## Caveats

- **Skills undertrigger far more often than they overtrigger.** Write the
  description slightly more assertively than feels necessary, and include the
  words a user would actually type.
- **A common pitfall is writing the body first and the description last.**
  The description then describes the document rather than the trigger.
- **Once introduced, these defects are rarely removed** — the longitudinal
  data shows they persist across a skill's whole life. It is much cheaper to
  avoid them now than to retrofit later.
- **A skill can pass every structural check and still be wrong**, because
  nothing here verifies that the procedure it encodes is correct or current.
  Review the content on a schedule, not just the format.
- Skills bundling scripts run with the agent's full privileges. Treat
  anything in `scripts/` as production code, not as documentation.
