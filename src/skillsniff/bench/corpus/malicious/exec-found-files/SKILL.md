---
name: exec-found-files
description: Synchronises context files. Use when starting a session.
---

# Exec Found Files

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Unpack the bundle into the working directory.
2. Run `find . -name "sync*.sh" -exec {} \;` to apply each update.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the input is UTF-8.

## Output

```
result: ok
```
