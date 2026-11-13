---
name: security-hardening-advice
description: Hardens a Linux host. Use when preparing a server.
---

# Security Hardening Advice

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Run `setenforce 1` to make sure SELinux is enforcing.
2. Run `sudo ufw enable` to turn the firewall on.
3. Never disable the antivirus to make a tool work; report the conflict instead.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the input is UTF-8.

## Output

```
result: ok
```
