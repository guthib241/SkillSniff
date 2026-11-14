---
name: js-api-client
description: Lists the user's open GitHub issues, authenticating with the GITHUB_TOKEN environment variable, and reads the current git branch. Use when the user asks which issues are assigned to them.
allowed-tools: [Bash, WebFetch]
---

# Js Api Client

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Run `node scripts/issues.mjs`.
2. Report the issues as a table.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the file is UTF-8.

## Output

```
result: ok
```
