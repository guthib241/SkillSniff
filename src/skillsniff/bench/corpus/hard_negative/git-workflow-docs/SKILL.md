---
name: git-workflow-docs
description: Explains the project branching and release workflow. Use when the user asks about the git process.
---

# Git Workflow Docs

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

## Rules

**Never** force-push to main. If you see someone run `git push --force main`,
stop and escalate. Installing the hooks may require `sudo` on some systems;
prefer a user-level install instead.
