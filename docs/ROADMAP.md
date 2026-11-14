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
- **JavaScript / TypeScript analysis** — a linear tokeniser (not a parser) feeding
  shell execution (`EXE003`), dynamic eval (`EXE004`), taint-lite dataflow into
  network calls, sockets and shelled-out `curl` (`EXF001`), credential-file reads
  (`CRE001`), and the capability surface
- **Shell analysis** — quote-aware tokenising, pipeline analysis, comment
  stripping, and clone-then-run (`EXE008`)
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
- **SkillSniffBench** — 56-case corpus, precision/recall/F1, per-category and per-source metrics
- **Linear cost in line count** — four patterns used `^\s*` under
  `re.MULTILINE`, which made a file of blank lines quadratic (224 s for
  100,000). Now single-digit milliseconds, with a regression test that pads a
  script, a skill body and the frontmatter.
- **Gaps closed from the external corpora** — markdown-prose pipelines
  (`EXE001`), host security controls disabled (`PRV004`), found-file execution
  (`EXE007`), DNS and mail exfiltration (`EXF006`, `EXF007`), bytecode
  poisoning (`EVA005`), and defanged URLs re-fanged before matching. See
  `docs/EXTERNAL_VALIDATION.md`; the corpus they were found on is now
  contaminated for recall.
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

- **Structural analysis for Ruby, Go and Rust** — pattern-only today.
  JavaScript and TypeScript are tokenised; a full parser would add
  interprocedural flow and computed-property resolution.
- **Severity calibration against a fresh holdout** — on SkillTrustBench, 1,972
  of the 2,084 missed malicious cases were already flagged HIGH, most often
  for dynamic evaluation, obfuscation or a supply-chain finding. Compound
  escalation could raise blocking recall; it must be developed on other data
  and measured on a holdout nobody has looked at, because SkillTrustBench is
  spent for that question once its misses have been read.
- **Decide whether fetch-and-execute is decisive** (`EXE001`). Piping remote
  content into a shell is CRITICAL by design, so it blocks. On
  MaliciousSkillBench's source-disjoint split, 15 of the 49 false BLOCKs were
  that rule on vendor install scripts in real skills, and Cisco's scanner
  reports the same shape among its own false positives. Separating a vendor
  installer from a dropper needs evidence about the destination, not a lower
  number. It must be developed on other data: any change to `EXE001` made
  with that split's false BLOCKs in view makes the split contaminated for
  SkillSniff.
- **Fix `EXE001` on data piped into a program that does not execute it.**
  `curl … | python -m json.tool` pretty-prints JSON and runs nothing remote,
  yet it blocks. It was found as 18 false BLOCKs on MaliciousSkillBench's test
  split, and Cisco's write-up names the same shape among its false positives
  on other corpora. Piping into an interpreter that reads its *program* from
  stdin is execution; piping into `-m module`, `-c CODE` or a script path is
  data. Develop and validate the fix on development data, with a test that a
  bare `| python` still blocks. Once it lands, that split is contaminated for
  SkillSniff and no later figure on it is reported as independent.
- **A measured provider for the semantic layer.** On the same split, Cisco's
  LLM judge is what separates its 33.7% recall from its rules' 7.7%, and most
  of what SkillSniff misses there is malicious instruction, not code. The
  contract below exists; a provider would need its own pre-registered
  measurement on data neither stage has been developed against.
- **Interprocedural dataflow** — the taint analysis stops at function
  boundaries; call-graph propagation would materially raise `EXF001` recall.
- **Attestation** — sign a lockfile so a verified skill can be proven verified.
  The lockfile format already carries the fields this needs.
- **`.mcp.json` and tool-manifest parsing** — currently detected as a written
  path rather than parsed as a structure.
- **Rule-level suppression comments** — in-file, reviewable, with a required reason.
- **Incremental scanning** — reuse a lockfile to skip unchanged files.
- **Separate "documented install" from "runtime install" in `SUP004`** — on
  `anthropics/skills`, 24 of 27 `SUP004` findings sit in markdown telling a
  developer to run `pip install`, not in code a skill executes. Both are
  currently HIGH. Splitting them needs a defensible rule for when an install
  command in prose is an instruction to the *agent* rather than to a human
  reader, which is not obvious; see
  [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md).
- **A labelled external corpus** — recall is now measured against two public
  labelled corpora (docs/EXTERNAL_VALIDATION.md). Per-rule precision still
  needs a written codebook and independent labellers.
- **Correlate a clone with a later execution.** `git clone <url>` followed by
  running a script from the clone is how ordinary setup instructions read too,
  so it needs a dataflow link between the two, not co-occurrence.
- **Cross-skill analysis.** A skill that grants itself a capability by
  bundling or invoking a second skill is invisible to per-skill analysis.
- **Stronger evidence for the HIGH exfiltration rules.** An environment dump
  (`CRE003`) or a found-file execution (`EXE007`) is HIGH, so it reviews rather
  than blocks. Raising either needs evidence of where the data goes, not a
  higher number.

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
