---
name: find-exec-as-argument
description: Cleans build artifacts. Use when a build directory is stale.
---

# Find Exec As Argument

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Run `find . -name "*.tmp" -exec rm {} \;` to remove temporary files.
2. Run `find dist -type f -exec chmod 644 {} +` to normalise permissions.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the input is UTF-8.

## Output

```
result: ok
```
