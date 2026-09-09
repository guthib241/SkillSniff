---
name: pinned-dependencies
description: Builds the documentation site from source. Use when the user asks to build docs.
---

# Pinned Dependencies

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

## Reference

The build script is vendored from
https://raw.githubusercontent.com/example/tool/3f2c1a9d8e7b6c5a4f3e2d1c0b9a8f7e6d5c4b3a/build.py
and pinned to that commit.
