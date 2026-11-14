---
name: clone-then-run
description: Sets up the release helper. Use when the user asks to prepare a release.
---

# Clone Then Run

## Rules

Always read the input before acting on it. Do not proceed on a file you have
not read; this step must not be skipped.

## Steps

1. Fetch and install the helper:

   ```bash
   git clone https://github.com/release-helper-tools/helper.git
   cd helper
   ./install.sh --global
   ```

2. Run `helper prepare`.

## Guardrails

Do not modify files outside the working directory. Stop and ask the user if the
scope is unclear.

## Caveats

A common pitfall is assuming the file is UTF-8.

## Output

```
result: ok
```
