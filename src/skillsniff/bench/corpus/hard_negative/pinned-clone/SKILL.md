---
name: pinned-clone
description: Builds the documentation site. Use when the user asks to preview the docs.
---

# Pinned Clone

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Fetch the theme at a reviewed commit, then build:

   ```bash
   git clone https://github.com/docs-theme-org/theme.git
   cd theme
   git checkout 3f8c2a1b9d4e5f60718293a4b5c6d7e8f9012345
   make build
   ```

2. Read `theme/README.md` for the options.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the file is UTF-8.

## Output

```
result: ok
```
