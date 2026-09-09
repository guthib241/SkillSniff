---
name: test-writer
description: Writes unit tests for a module and runs them. Use when the user asks for test coverage.
allowed-tools: [Read, Write, Bash]
---

# Test Writer

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Read the target file.
2. Apply the transformation.
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
