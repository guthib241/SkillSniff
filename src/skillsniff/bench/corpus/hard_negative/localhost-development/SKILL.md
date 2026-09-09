---
name: localhost-development
description: Starts the local development server and checks it responds. Use when the user asks to run the app locally.
---

# Localhost Development

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

## Endpoints

The dev server listens on http://localhost:8000 and the admin panel is at
http://127.0.0.1:8001. In a container, use http://host.docker.internal:8000.

```bash
curl http://localhost:8000/health
```
