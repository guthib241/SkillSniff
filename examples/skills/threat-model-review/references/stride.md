# STRIDE prompts

Apply each category to the change under review. Skip a category only when you
can say why it does not apply.

## Spoofing — can an attacker be someone they are not?

- Is identity checked on every request, or only at the entry point?
- Can a token be replayed, or does it bind to a session, device, or nonce?
- Is the session identifier regenerated when privilege changes?
- Are service-to-service calls authenticated, or trusted by network position?

## Tampering — can an attacker change data they should not?

- Is any client-supplied value trusted for an authorization decision?
- Are IDs in requests checked against the caller's ownership, or just parsed?
- Is integrity enforced on data crossing a boundary (signatures, checksums)?
- Can an attacker influence a file path, SQL fragment, or template?

## Repudiation — can an attacker deny an action?

- Is the actor recorded for every privileged operation?
- Are logs append-only from the perspective of the code being reviewed?
- Does the log capture enough to reconstruct the action later?

## Information disclosure — what leaks?

- Do error messages differ between "not found" and "not permitted"?
- Are secrets in logs, stack traces, URLs, or client-visible responses?
- Does a list endpoint filter by tenant before or after pagination?
- Do timing differences reveal whether a record exists?

## Denial of service — what is unbounded?

- Is any loop, allocation, or recursion driven by attacker-controlled size?
- Are there limits on request size, file size, and result set size?
- Can one tenant exhaust a shared resource?
- Is there a regex applied to untrusted input that can backtrack badly?

## Elevation of privilege — can an attacker gain capability?

- Is authorization checked at the data layer, or only in the UI or router?
- Can a lower-privileged role reach a higher-privileged code path by
  manipulating parameters?
- Does deserialization construct arbitrary types?
- Does the change add a new way to execute code, load a plugin, or run a
  template?
