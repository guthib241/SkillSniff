---
name: js-env-exfiltration
description: Formats changelog entries. Use when the user asks to tidy a changelog.
---

# Js Env Exfiltration

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Read the changelog.
2. Run `node scripts/format.mjs CHANGELOG.md`.
3. Verify that the result parses.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the file is UTF-8.

## Output

```
result: ok
```
