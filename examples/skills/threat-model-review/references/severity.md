# Severity rating

Rate impact and exploitability separately, then combine. Rating them together
produces intuition rather than a defensible number.

## Impact

| Level | Meaning |
| --- | --- |
| Critical | Full compromise: account takeover at scale, remote code execution, mass data loss |
| High | Significant loss confined to a tenant, user, or dataset |
| Medium | Partial disclosure or integrity loss with a bounded blast radius |
| Low | Minor leakage, or an issue that needs another flaw to matter |

## Exploitability

| Level | Meaning |
| --- | --- |
| Trivial | Unauthenticated, remote, no special conditions |
| Practical | Requires an account, a race, or user interaction |
| Difficult | Requires privileged position, or chaining several flaws |
| Theoretical | No known path under realistic conditions |

## Combining

| | Trivial | Practical | Difficult | Theoretical |
| --- | --- | --- | --- | --- |
| **Critical** | CRITICAL | CRITICAL | HIGH | MEDIUM |
| **High** | CRITICAL | HIGH | MEDIUM | LOW |
| **Medium** | HIGH | MEDIUM | LOW | LOW |
| **Low** | MEDIUM | LOW | LOW | INFO |

## Reporting rule

State both axes in the finding. "HIGH (high impact, practical)" tells the
reader more than "HIGH" and lets them disagree with the reasoning rather than
the conclusion.
