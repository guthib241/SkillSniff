# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-09-09

Rebuild of the project from a SKILL.md linter into a security, trust and
capability analyser. The command name, package name, rule identifiers and output
formats all change; treat this as a new tool rather than an upgrade.

### Added

- **Capability analysis.** 21 capabilities inferred separately from the
  description, declared tools, instruction text, bundled code, dependency
  manifests and external references, then compared — which is what makes a
  mismatch between claim and behaviour expressible (`CON001`–`CON004`).
- **Dataflow analysis.** Python AST with intraprocedural taint tracking from
  secret sources to network sinks, through assignments, f-strings and
  containers, with the authentication shape recognised and excluded (`EXF001`).
- **Archive inspection.** ZIP and TAR, recursive, entirely in memory, never
  extracted; Zip Slip, decompression bombs, depth and entry limits.
- **Unicode and encoding analysis.** Zero-width, bidirectional, Unicode tag
  characters, homoglyphs; recursive base64/base32/hex/percent/escape decoding
  with origin attribution.
- **Coverage ledger.** Every refusal recorded and reported; coverage confidence
  gates the verdict.
- **Trust graph** with typed nodes and edges, rendered as a tree by `inspect`.
- **Compound-risk rules** including the lethal trifecta (`CON010`–`CON014`).
- **`lock` / `verify`** — content hashes, capability snapshot, provenance, and
  graded change detection.
- **`diff`** — behavioural comparison, flagging new capability under an
  unchanged description.
- **`policy`** — deterministic policy-as-code with ALLOW/REVIEW/DENY and a named
  clause behind every decision.
- **`inspect`** — full trust report.
- **`benchmark`** — SkillSniffBench, 41 labelled cases with precision/recall/F1.
- **SARIF 2.1.0 output** with full rule metadata for GitHub code scanning.
- Configuration file discovery, rule selection, severity thresholds, resource
  limits, path exclusions.

### Changed

- **Risk is no longer a single score.** Independent dimensions with a gated
  verdict. A critical security finding is decisive regardless of documentation
  quality; previously excellent docs could numerically offset an exfiltration
  path.
- **A scan that could not read the artifact returns `INCONCLUSIVE`, never
  `CLEAR`.**
- **Verdicts never claim safety.** `CLEAR` reads "no issues detected by the
  enabled checks".
- **Multi-skill results are worst-of, not averaged.** Averaging hid one
  dangerous skill behind nine clean ones.
- **Findings carry evidence structurally** — path, line, excerpt, decode chain —
  and cannot be constructed without it.
- **Severity and confidence are separate fields.**
- **Frontmatter parsing is robust.** PyYAML when available, otherwise a fallback
  supporting block scalars with chomping, flow and block collections, and
  arbitrary nesting; parity between the two is tested.
- Rule identifiers moved to a 16-family taxonomy.
- Exit codes distinguish "found something" (1) from "the tool failed" (3).

### Fixed

- `explain` covered only the security rule pack, so `explain SPEC005` failed.
  All rule metadata now derives from one registry.
- Only the first match per rule per file was reported.
- Bytecode files were excluded from traversal by default, so a `.pyc` payload
  was never discovered.
- A skill's own frontmatter parser handled one level of nesting and discarded
  block-scalar indentation.
- No symlink, path-traversal, archive, or resource limits existed.
- An invalid `--fail-on` value crashed with a traceback instead of a usage error.

### Security

- The scanner performs no subprocess execution and no dynamic evaluation, both
  asserted by an AST walk over the source tree.
- Archives are never extracted to disk.
- Credentials are redacted in all output.
- Lockfiles record relative paths only, and strip credentials from remote URLs.

## [0.1.0]

Initial release as Assay: a deterministic SKILL.md linter with specification,
authoring-smell and security rulesets.
