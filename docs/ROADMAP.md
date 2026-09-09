# Roadmap

Four categories, kept strictly separate. A planned feature described in the
present tense is a false capability claim, and for a security tool that is a
defect rather than marketing.

---

## IMPLEMENTED

Working, tested, and covered by the benchmark corpus.

- **Specification analysis** — frontmatter structure, required fields, types,
  name grammar, directory match, length limits, allowed keys, body presence,
  broken internal references (`SPEC001`–`SPEC010`)
- **Security rules** — 59 rules across 14 security families
- **Python AST analysis** — capability extraction, `shell=True`, dynamic eval,
  and intraprocedural taint-lite dataflow with authentication-shape recognition
- **Shell analysis** — quote-aware tokenising, pipeline analysis, comment stripping
- **Unicode threat analysis** — zero-width, bidi, tag characters, variation
  selectors, private-use, mixed-script homoglyphs
- **Recursive decoding** — base64, base32, hex, percent, escapes, Unicode tags,
  to depth 3, with origin attribution
- **Archive inspection** — ZIP and TAR, recursive, in memory, never extracted,
  with traversal, bomb, depth and entry guards
- **Capability model** — 21 capabilities inferred from 5 independent sources
- **Capability mismatch and compound risk** — including the lethal trifecta
- **Trust graph** — typed nodes and edges, tree rendering
- **External resource classification** — offline mutability analysis
- **Dependency analysis** — pip, npm, pyproject, install hooks
- **Multi-dimensional risk model** with gated verdicts
- **Coverage ledger** — every refusal recorded, confidence derived from it
- **Lock / verify** — content hashes, capability snapshot, provenance, graded change detection
- **Behavioural diff** — capability, dependency, external and verdict deltas
- **Policy engine** — deterministic, testable, every decision names its clause
- **SkillSniffBench** — 41-case corpus, precision/recall/F1, per-category and per-source metrics
- **Output** — terminal, JSON, SARIF 2.1.0, Markdown, trust report
- **Configuration** — file discovery, rule selection, severity thresholds, limits
- **Scanner hardening** — no subprocess, no eval, no extraction, resource budgets

---

## PLANNED

Designed and intended, not yet built.

- **Non-Python AST analysis** — JavaScript and TypeScript first, since they are
  the second most common bundled language. Currently pattern-only.
- **Interprocedural dataflow** — the taint analysis stops at function
  boundaries; call-graph propagation would materially raise `EXF001` recall.
- **Baseline files** — accept a recorded set of known findings so a repository
  can adopt SkillSniff without fixing everything first.
- **Attestation** — sign a lockfile so a verified skill can be proven verified.
  The lockfile format already carries the fields this needs.
- **`.mcp.json` and tool-manifest parsing** — currently detected as a written
  path rather than parsed as a structure.
- **Rule-level suppression comments** — in-file, reviewable, with a required reason.
- **Incremental scanning** — reuse a lockfile to skip unchanged files.

---

## EXPERIMENTAL

Interfaces exist or are sketched; behaviour is not guaranteed and no findings
from these paths are enabled by default.

- **Semantic analysis layer.** An optional LLM pass for intent analysis,
  description/behaviour mismatch, and contextual injection classification.
  Design commitments already fixed: static analysis must remain fully functional
  without it; scanned content must never become system or developer
  instructions; artifact content must be passed as clearly-delimited untrusted
  data; every output must be labelled a semantic judgment, carried on findings
  as `advisory: true`, and never presented as fact. **No implementation exists.**
- **Behavioural sandbox.** Optional dynamic analysis observing filesystem,
  network, DNS, process creation and environment access, with synthetic canary
  credentials in a disposable environment under strict resource limits. The
  correct interfaces matter more than a quick approximation: a sandbox that
  leaks is worse than none. **No implementation exists**, deliberately, rather
  than an unsafe approximation.

---

## RESEARCH

Open questions where the right approach is not yet clear.

- **Cross-platform behavioural divergence.** A skill's security properties can
  change between agent ecosystems — a tool grant that is scoped on one platform
  and unscoped on another. Modelling this requires per-platform semantics that
  are not stable enough to encode, and claiming compatibility without testing it
  would be a false claim.
- **Source-disjoint evaluation.** The single most valuable missing measurement.
  Requires a labelled corpus this project did not write. Until it exists, the
  reported metrics describe a regression suite.
- **Semantic-equivalence evasion.** How much of the rule set survives an
  attacker who rewrites payloads to preserve meaning while avoiding every
  pattern? Almost certainly less than the benchmark suggests.
- **Multilingual detection.** The largest coverage gap. Whether it is best
  addressed by translated pattern sets or by the semantic layer is unresolved.
- **Trust-graph reachability.** The graph currently describes structure. Querying
  it for paths from an untrusted node to a privileged capability would turn the
  compound rules from co-occurrence checks into genuine reachability analysis.
