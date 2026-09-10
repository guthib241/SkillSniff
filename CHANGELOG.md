# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `INJ003` (concealment) fired on the phrase "without asking" in ordinary
  authoring advice — "a spec written without asking the user anything restates
  the request" is advocating asking, not concealing. The rule was conflating two
  different concerns: concealment is about hiding what was done, while failing
  to ask is about permission. `without asking` no longer matches concealment,
  and instruction-level permission bypass moved to `PRV001` behind a pattern
  requiring an actual imperative verb. Found by scanning skills written for the
  predecessor tool, which is the kind of input the internal corpus cannot
  provide.

### Added

- **Baseline suppression** (`skillsniff baseline`, `scan --baseline`). The
  practical barrier to adopting any analyser on an existing repository is that
  day one it reports everything at once, and a team that cannot reach zero in
  one sitting turns the gate off permanently. A baseline records what exists
  today so the gate can be enabled immediately and enforce only what happens
  next. Findings are fingerprinted by rule, file and normalised evidence rather
  than by line number, so reformatting does not resurrect suppressed findings
  and moving code does not mask new ones; recorded counts are respected, so a
  third occurrence of a twice-baselined finding is still reported. Suppression
  is stated in every report, verdicts are re-derived after it, and a coverage
  gap cannot be baselined away.
- **GitHub Action** (`action.yml`). Composite action needing no secrets:
  scans, uploads SARIF, comments the capability diff against the pull request
  base, optionally evaluates a policy, and exposes `verdict`, `findings` and
  `critical` as outputs. SARIF and the job summary are published before the
  threshold is enforced, so a failing gate still leaves the full report.
- **Pre-commit hooks** (`.pre-commit-hooks.yaml`). `skillsniff` scans only the
  skills the commit touched; `skillsniff-all` scans the tree. Each changed file
  is resolved up to the skill directory that owns it and that skill is scanned
  whole, because capability mismatch and the compound-risk rules are properties
  of a skill and cannot be evaluated from one file.
- **`skillsniff init`**. Scaffolds a config, a policy and a CI workflow, with
  three profiles (balanced, strict, advisory), pointed at wherever the
  repository's skills actually are rather than assuming `./skills`. Everything
  it writes is asserted to load back into the tool.
- **Reference skills** in `examples/skills/`, scanned by CI under `--strict` on
  every commit. Written for this project's predecessor before any current rule
  existed, so they are the only content not authored alongside the rules that
  judge it.
- **Release workflow.** Re-runs the full gate on the tagged commit rather than
  trusting that CI passed, checks that the tag, the package version, the version
  `action.yml` pins and the changelog entry all agree, verifies the wheel ships
  no corpus content and no runtime dependency, then publishes via PyPI trusted
  publishing (no stored token).

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

### Performance

- Text projections (normalised view, comment-blanked view) are memoised per file
  for the life of a scan. They had been recomputed once per rule, which on a
  1 MB file meant normalising the same megabyte 45 times.
- Homoglyph folding and invisible-character stripping use `str.translate`
  rather than per-character generators, removing ~22 million Python-level
  iterations on a 1 MB input.

Together these are a 2–6× improvement depending on input shape; the benchmark
corpus went from 9.2 to 4.0 ms per skill. Measurements and regression tests are
in `docs/LIMITATIONS.md` and `tests/integration/test_performance.py`.

### Security

- The scanner performs no subprocess execution and no dynamic evaluation, both
  asserted by an AST walk over the source tree.
- Archives are never extracted to disk.
- Credentials are redacted in all output.
- Lockfiles record relative paths only, and strip credentials from remote URLs.

## [0.1.0]

Initial release as Assay: a deterministic SKILL.md linter with specification,
authoring-smell and security rulesets.
