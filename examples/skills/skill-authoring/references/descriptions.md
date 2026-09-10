# Writing descriptions that trigger

The description is the only part of a skill that is always in the agent's
context. Everything else loads after the routing decision has already been
made. If the description is wrong, the rest of the file never runs.

## The shape

```
[What it does, third person] + [When to use it] + [Trigger keywords]
```

All three parts are load-bearing. Most published skills have only the first.

## Failure patterns

| Pattern | Example | Why it fails |
| --- | --- | --- |
| What without when | "Analyses performance benchmarks." | The agent knows what it is, never learns when to reach for it |
| First or second person | "I help you review code." | Inconsistent point of view degrades matching |
| Vague verb | "Helps with testing." | Matches everything and therefore nothing |
| Jargon-only trigger | "Use for OTLP span ingestion." | Real users do not type this |
| Restates the name | "The pdf-tools skill for PDF tools." | Adds no routing signal |
| Contains XML tags | "Handles `<config>` files." | Injection vector, and fails validation |

## Trigger keywords

List the words a user would actually type, including the informal ones. A
skill about database migrations should cover: migration, schema change,
ALTER TABLE, downtime, locking, "is this safe to run".

Cover three registers:

1. **The technical term** — "WCAG contrast ratio"
2. **The common term** — "accessibility", "a11y"
3. **The symptom** — "screen reader can't read the button"

Users in trouble describe symptoms, not terms of art.

## Undertriggering

Agents skip useful skills more often than they invoke irrelevant ones. Bias
toward assertive phrasing:

```
Weaker:  Can be used to review dashboards.
Better:  Reviews dashboards for clarity and correctness. Use whenever the
         user mentions dashboards, charts, metrics displays, or asks how to
         visualise data, even if they do not use the word "dashboard".
```

## Length

The ceiling is 1024 characters, but most good descriptions are 200 to 500.
Past that you are usually writing body content in the wrong place. Under 100
you are usually missing the trigger.

## Testing the description

Write three phrasings a real user might send. If the description would not
obviously match all three, it is incomplete. Include phrasings that do not
contain the skill's name — those are the ones that fail in practice.
