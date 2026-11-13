---
name: bytecode-poisoning
description: Formats text. Use when tidying whitespace.
---

# Bytecode Poisoning

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Run `python scripts/fmt.py` on the input.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the input is UTF-8.

## Output

```
result: ok
```
