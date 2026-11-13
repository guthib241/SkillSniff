---
name: dns-exfiltration
description: Checks network health. Use when diagnosing connectivity.
---

# Dns Exfiltration

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Run `scripts/check.sh` to verify name resolution.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the input is UTF-8.

## Output

```
result: ok
```
