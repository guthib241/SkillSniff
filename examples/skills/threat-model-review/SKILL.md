---
name: threat-model-review
description: Threat-models a proposed code change or feature and reports concrete attack paths with severity and mitigations. Use when the user asks for a security review, threat model, or risk assessment; when a change touches authentication, authorization, sessions, file uploads, deserialization, payments, or PII; or whenever the user asks whether a change is safe to ship.
license: MIT
metadata:
  version: 1.0.0
  category: security
---

# Threat model review

Produce a threat model for a specific change, not a generic security lecture.
Every finding names an attacker, a path, and a fix.

## Rules

These constraints are not optional and must not be skipped, even when the
change looks small or the user says it is urgent:

1. **Read the actual code before modelling it.** Never threat-model from a
   description alone. If the code is not available, stop and ask for it.
2. **Every finding cites a file and line.** A finding with no location is a
   guess, not a finding.
3. **Never report a vulnerability without a mitigation.** An unactionable
   finding wastes the reader's time.
4. **Do not write exploit code.** Describe the attack path in prose. Proof of
   concept belongs in a controlled disclosure process, not a review comment.
5. **Say what was not covered.** An incomplete review presented as complete is
   worse than no review, because it manufactures false confidence.

## Steps

1. **Establish the trust boundary.** Identify where untrusted input enters the
   change and what privilege it reaches. Write this down before analysing
   anything; it constrains everything that follows.
2. **Inventory the assets.** List what an attacker would want here:
   credentials, PII, funds, compute, or the ability to pivot.
3. **Walk the STRIDE categories** against the change. Load
   `references/stride.md` for the prompts to apply in each category.
4. **Trace each candidate finding to a concrete path.** Attacker position →
   input → the code that mishandles it → the impact. Discard anything you
   cannot trace end to end.
5. **Rate severity** using `references/severity.md`. Rate impact and
   exploitability separately; do not collapse them into one intuition.
6. **Propose a mitigation per finding**, preferring a structural fix over a
   filter. Note when the structural fix is out of scope for this change.
7. **Verify the review before delivering it.** Re-read each finding and
   confirm the cited line actually contains what the finding claims. Drop any
   finding that fails this check.

Track progress as you go:

- [ ] Trust boundary written down
- [ ] Assets inventoried
- [ ] STRIDE walked
- [ ] Each finding traced end to end
- [ ] Each finding severity-rated
- [ ] Each finding has a mitigation
- [ ] Citations verified against the source

## Guardrails

Stop and ask the user rather than guessing when:

- The change touches cryptography and the algorithm or mode is unclear. Never
  approve a hand-rolled cryptographic construction; recommend a reviewed
  library instead.
- The system's authentication model is not visible in the diff.
- The change is infrastructure-as-code and the deployed state may differ.

Do not extend the review to unrelated parts of the codebase. Scope creep in a
security review buries the findings that matter under ones that do not.

Refuse to produce a review that only says "looks fine". If nothing was found,
say what was examined and what would change the conclusion.

## Output

Report findings highest severity first, using this template:

```
## Threat model: <change name>

**Scope:** <what was reviewed>
**Not covered:** <what was excluded and why>
**Trust boundary:** <where untrusted input enters, and the privilege it reaches>

### <SEVERITY> — <short title>

- **Attacker:** <who, and what position they need>
- **Path:** <input → mishandling → impact>
- **Location:** `path/to/file.py:42`
- **Impact:** <what they gain>
- **Mitigation:** <the fix; note if structural and out of scope>

### Residual risk

<what remains after the proposed mitigations>
```

Worked example of a single finding:

```
### HIGH — Session fixation on login

- **Attacker:** unauthenticated, able to set a cookie on the victim's browser
- **Path:** attacker plants a known session id → victim authenticates →
  server reuses the same id → attacker's cookie is now authenticated
- **Location:** `auth/session.py:88`
- **Impact:** full account takeover without credentials
- **Mitigation:** regenerate the session identifier on privilege change.
  One line at the end of `login()`.
```

## Caveats

- **A clean review is not a safe system.** This finds design and code-level
  issues in a bounded change. It does not replace dependency scanning, secret
  scanning, or a penetration test.
- **The most common failure mode is modelling the code you expected rather
  than the code that is there.** When a finding feels obvious, re-read the
  source before writing it up.
- **Severity inflation destroys trust.** If everything is critical, the reader
  stops reading. Reserve the top severity for findings that are both
  high-impact and reachable.
- If the change is large enough that step 3 feels unmanageable, split the
  review by trust boundary and report separately. Do not skim.
