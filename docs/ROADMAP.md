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
- **Baseline suppression** — line-independent fingerprints, count-aware, always
  reported, and unable to suppress a coverage gap
- **Adoption paths** — GitHub Action, pre-commit hooks, `skillsniff init`
  scaffolding, and a release workflow with trusted publishing

---

## PLANNED

Designed and intended, not yet built.

- **Non-Python AST analysis** — JavaScript and TypeScript first, since they are
  the second most common bundled language. Currently pattern-only.
- **Interprocedural dataflow** — the taint analysis stops at function
  boundaries; call-graph propagation would materially raise `EXF001` recall.
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

- **Semantic analysis layer** (`skillsniff.semantic`). **The contract exists and
  is tested; no provider is implemented and none is enabled.** An optional LLM
  pass for intent analysis, description/behaviour mismatch, and contextual
  injection classification. Four properties are enforced by the interface rather
  than left to convention, and each has a test:
  - nothing in the core imports the package, so static analysis cannot come to
    depend on it;
  - artifact content is wrapped in an untrusted envelope and a request whose
    content contains the delimiter is *refused rather than escaped*, because
    escaping is an arms race against an attacker who controls the whole input;
  - findings are forced to `advisory: true` and capped at MEDIUM confidence and
    HIGH severity on the way out, so a model's opinion can never reach the
    critical-finding gate or fail a build alone;
  - the default `NullProvider` makes no call, so enabling the layer without
    configuring a provider is a visible no-op.

  What remains: an actual provider, prompt construction, and evaluation of
  whether its judgments are worth the latency.

- **Behavioural sandbox** (`skillsniff.sandbox`). **The contract exists and is
  tested; no runner is implemented and the default refuses.** Optional dynamic
  analysis observing filesystem, network, DNS, process creation and environment
  access, with synthetic canary credentials whose *touch* is the signal.

  The default `RefusingRunner` raises rather than returning an empty report,
  because an empty report reads as "nothing happened". `BehaviourReport`
  distinguishes a completed run from a timed-out or crashed one and refuses to
  support a negative conclusion from the latter. Correlation reports behaviour
  that static analysis missed, and deliberately **never** reports the reverse:
  "not exercised in this run" is not "not present", and treating it as such is
  how dynamic analysis talks people out of true findings. A test asserts the
  package imports no execution primitive at all.

  `SANDBOX_REQUIREMENTS` records the seven properties any implementation must
  have before it may be enabled by default. What remains is an implementation
  that meets them — which is a substantial piece of infrastructure, and an
  approximation would be worse than nothing because a leaky sandbox produces a
  clean result carrying far more apparent authority than a static one.

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
