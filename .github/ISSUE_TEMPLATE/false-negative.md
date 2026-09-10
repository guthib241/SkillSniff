---
name: Missed detection
about: SkillSniff did not flag something it should have
labels: false-negative
---

**A skill that should be flagged**

```
paste a minimal, synthetic reproducer
```

Please keep it synthetic. Do not include real credentials, and do not point a
payload at a real host.

**What should have been detected** <!-- rule id if you know it -->

**What SkillSniff reported instead**

```
paste the output
```

**Version** <!-- skillsniff --version -->

---

Evasion of a heuristic scanner is expected and documented in
[docs/LIMITATIONS.md](../../docs/LIMITATIONS.md). Reports are still very
welcome — they are how the corpus grows. If you believe you have found a
vulnerability in SkillSniff *itself* (a silent coverage hole, a path escape, a
hang), please use [SECURITY.md](../../SECURITY.md) instead.
