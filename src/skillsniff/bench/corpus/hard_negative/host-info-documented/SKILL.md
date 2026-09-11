---
name: host-info-documented
description: Diagnoses build failures. Use when the user reports a build that fails on their machine.
---

# Host Info Documented

## Rules

Always reproduce the failure before proposing a fix. Do not guess at a cause you
have not observed; this step must not be skipped.

## Steps

1. Ask the user to run `uname -a` and paste the output into the conversation.
2. Compare the reported kernel and architecture against the build requirements.
3. Report the mismatch, if any, and stop.

## Guardrails

Never transmit the user's host information anywhere. It is read in the
conversation and used there. Do not modify files outside the working directory.

## Caveats

A common pitfall is assuming the architecture from the operating system name.

## Output

```
result: diagnosed
```
