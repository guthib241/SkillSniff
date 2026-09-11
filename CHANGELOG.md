# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **Five false positives found by scanning skills this project did not write.**
  Before this change SkillSniff returned `BLOCK` on `anthropics/skills` — nine
  CRITICAL findings, all wrong — while the self-authored benchmark reported a
  false-positive rate of 0.000. Each fix is a narrowing with a stated semantic
  basis, each has a regression test named after the skill that exposed it, and
  each is paired with a test asserting the real attack shape still fires.
  Detection on the malicious corpus was unchanged: 18 CRITICAL findings and 3
  blocked skills before and after.
  - `PRV001` read "don't ask the user **for a key**" as a safety-control
    bypass. Declining to solicit a credential is the opposite of bypassing
    permission, so the object of the asking now decides it.
  - `PRV001` treated an example system prompt quoted in a markdown blockquote
    as an instruction. Quotation is not assertion; blockquotes now count as
    documentation framing, which downgrades to LOW rather than suppressing.
  - `EXF002` matched the bare word "HTTP" in the prose "HTTP/2 protocol error"
    and swallowed 200 characters that happened to contain a key name. The
    `http` branch now requires an HTTPie-shaped invocation.
  - `MEM001` matched `agents.md` *inside* `managed-agents.md`, and `/memory.md`
    inside a URL path. Naming a file is not writing to it.
  - `CRE003` used `$` under `re.MULTILINE`, so any prose line ending in the
    word "env" became a wholesale environment dump. `env` must now be in
    command position.
- `EXF003` missed `paste.c-net.org`, the exfiltration endpoint in Snyk's
  published ToxicSkills demo skill. Paste hosts are now recognised
  structurally by their leftmost label as well as by the curated list.
- Stale counts across the README and docs: the rule catalogue said 87 rather
  than 88, the benchmark corpus said 41 cases rather than 43 in five files, and
  the median scan time was published as 13.4 ms in two places while a third
  said 4.0 ms. Re-measured at 4.5 ms per skill, median of 7 runs on one core.
  The `claims` CI job now prevents this class of drift.
- A `CLEAR` verdict printed "No issues detected by the enabled checks" even
  when specification and quality findings existed, because those dimensions are
  deliberately isolated from the verdict gates. The verdict was right and the
  sentence was not, which is the one place this tool could talk a reader out of
  looking at a real finding. Exposed by `skill-with-commands` in
  `snyk-labs/toxicskills-goof`, which reported `CLEAR` over an invalid name and
  six authoring findings.

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

- **`CLAIMS.md` and a `claims` CI job.** Every figure in the README now traces
  to how it was obtained — MEASURED (a command in this repository), CITED (an
  external source, quoted as that source states it), or DERIVED (a count,
  regenerable). `scripts/claims_lint.py` fails the build if the README carries
  a figure the ledger does not account for. It caught real drift on its first
  run: adding one rule left "87 rules" in two places and "41-case corpus" in
  five files, and two documents disagreed about the median scan time by 3x.
  The file also records the claims deliberately *not* made — no score, no
  letter grade, no "safe" or "smell-free", no per-rule precision, and not
  "production ready".
- **`EXF005` — system reconnaissance output sent to a remote host.** A network
  command whose payload contains command substitution running `uname`,
  `whoami`, `hostname` or similar. This was a genuine coverage gap: the skill
  that Snyk's ToxicSkills corpus documents as malicious posts `uname -a` to a
  paste site, and SkillSniff saw the shell execution but had no rule for the
  payload. Rated HIGH rather than CRITICAL — host fingerprinting is a precursor
  and legitimate installers do it — so the labelled sample still lands on
  `REVIEW` rather than `BLOCK`. That gap is reported rather than tuned away.
- **`docs/EXTERNAL_VALIDATION.md` and `scripts/external_eval.py`** — a
  source-disjoint evaluation against pinned public corpora written by other
  people. Reports a false `BLOCK` rate of 0/20 on `anthropics/skills`, Wilson
  95% CI [0.000, 0.161], and states plainly that recall remains unmeasured
  because no independently labelled corpus of agent skills is public.
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
