# Interrogation questions

Work through these against the request. Most reveal nothing; the few that do
are the reason to run the whole list. Ask the user any the request leaves
unanswered.

## Scope

- What is the smallest version that would still be worth shipping?
- What would a reader reasonably assume is included that is not?
- Is this one feature, or several that arrived in one sentence?
- What happens if we ship nothing?

## Users and permissions

- Who can do this? Who can see that it was done?
- Does an administrator do this on someone else's behalf? What is recorded?
- What does a user with no data see the first time?
- Can two people do this at once? What happens?

## Data

- What is created, changed, or deleted?
- Is deletion soft or hard? Who can recover it, and for how long?
- Does anything here become part of an export, a backup, or an audit log?
- What is the largest realistic input? What happens just past it?
- Does any of this cross a tenant, region, or residency boundary?

## States

- Empty, loading, partial, error, offline, stale, conflicting.
- What does the user see while a slow operation runs?
- What happens if the user navigates away mid-operation?
- Is the operation idempotent if retried?

## Failure

- What is the behaviour when the dependency is down?
- Is failure silent, visible, or blocking?
- Can the system end up half-done? How does it recover?
- Who finds out when this breaks in production?

## Money and trust

- Does this move money, change a price, or affect a quota?
- Is any part of it irreversible from the user's point of view?
- Would a user be surprised by any side effect?

## Boundaries

- What existing behaviour changes as a side effect?
- What breaks for users who have already adopted a workaround?
- Does this need a migration, a backfill, or a feature flag?
- What is the rollback plan?

## Success

- How will we know this worked, a month after shipping?
- What measurement exists today to compare against?
- What result would make us remove this feature again?
