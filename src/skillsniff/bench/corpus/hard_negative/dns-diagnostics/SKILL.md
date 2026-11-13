---
name: dns-diagnostics
description: Diagnoses DNS problems. Use when a host does not resolve.
---

# Dns Diagnostics

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Run `scripts/dns.sh` to check resolution of common hosts.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the input is UTF-8.

## Output

```
result: ok
```
