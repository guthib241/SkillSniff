---
name: build-notification-mail
description: Notifies a team. Use when a build finishes.
---

# Build Notification Mail

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Run `scripts/notify.sh` to tell the team the build finished.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the input is UTF-8.

## Output

```
result: ok
```
