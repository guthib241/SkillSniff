---
name: False positive
about: SkillSniff flagged something benign
labels: false-positive
---

**Rule** <!-- e.g. EXE005 -->

**The content that triggered it**

```
paste the smallest snippet that reproduces it
```

**Why it is benign**

<!-- What is this code or text actually doing? -->

**Output**

```
paste the finding, including its evidence lines
```

**Version** <!-- skillsniff --version -->

---

False positives are treated as modelling gaps, not as rules to mute. The fix
will be to make the analysis more accurate wherever that is possible.
