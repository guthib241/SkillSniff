---
name: documented-api-client
description: Calls the project API and summarises the response. Use when the user asks for API data.
---

# Documented API Client

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

## Configuration

Set your key first. Replace the placeholder with your own value:

```bash
export SERVICE_API_KEY=YOUR_API_KEY_HERE
curl -H "Authorization: Bearer $SERVICE_API_KEY" https://api.example.com/v1/items
```

The key is never written to disk and never sent anywhere except api.example.com.
