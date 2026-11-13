# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- **Extensionless scripts were never read.** A file with no extension was
  classified by its name alone, as binary, so `bin/run` opening `#!/bin/sh` or
  `#!/usr/bin/env node` reached no lexical or structural rule: the most
  ordinary place to ship an executable script was the easiest place to hide
  one. A shebang now makes the file text, and JavaScript when the interpreter
  is `node`, `deno`, `bun` or `zx`.

- **Line count is no longer an attack surface.** Four patterns used `^\s*`
  under `re.MULTILINE`, so a file of blank lines cost O(n²): 100,000 of them
  took a scan to 224 s, and before the coverage fix that stall forced a
  `CLEAR`. The patterns are `FRAME_IMPERSONATION`, two quality patterns, and
  the frontmatter alias guard, which runs before any rule. All four are now
  linear. Trail of Bits' `csv-summarizer` scans in 301 ms instead of 224 s, and
  the environment dump hidden after its padding is now reported.

### Added

- **Measured once on skills the rules had never seen, as pre-registered.**
  SkillTrustBench v1.0, 5,516 expert-labelled cases: malicious recall
  **0.271**, CI [0.255, 0.288] — below the pre-registered 0.40 floor, so the
  tool is not fit as a gate and stays advisory by default. False BLOCK rate on
  normal cases 0.040, CI [0.031, 0.050], so the precision claim stands, for
  BLOCK only; 73.9% of normal cases get a REVIEW, so a REVIEW is weak
  evidence. One advance prediction failed: the wild-style families scored
  highest, not lowest. ClawHub's holdout, as agreement with another scanner:
  2 of 24 malicious rows blocked, 3.7% of clean rows blocked. Every miss is
  published by case id in `docs/results/holdout-2026-11-13/`; no rule was
  changed in response.

- **JavaScript and TypeScript analysis** (`analysis/jsscan.py`): a tokeniser,
  not a parser, so it adds no dependency, and it knows strings, template
  literals, comments and regular expressions from code. It feeds `EXE003`
  (`child_process.exec`, `spawn` with `shell: true` or `sh -c`, shelljs, zx),
  `EXE004` (`eval`, `new Function`, `vm` on runtime values), `EXF001` (a
  secret-named variable, the whole environment or a credential file reaching
  `fetch`, axios, `http(s)`, a socket, a mail transport, a DNS lookup or a
  shelled-out `curl`) and `CRE001`, plus the capability surface. The Python
  rule's authentication exception carries over, extended to a destination
  whose host is fixed even when its path is built at runtime. Every stage is
  linear; a megabyte of crafted input takes under 3 s, and running out of the
  work budget is recorded as an `analysis-truncated` coverage gap.
- **`EXE008` code run from an unpinned clone.** `git clone` followed by
  running something inside the checkout (a script in it, its build or install
  hooks after `cd`, a `pip install` of it). The link from the clone's directory
  to what runs is followed, not guessed; a clone that is only read, or one
  pinned to a full commit hash first, is not reported. HIGH. 94 rules.
- **DNS and mail exfiltration block when both halves are shown.** `EXF006` and
  `EXF007` stay HIGH for the shape alone, and become CRITICAL when the data is
  shown to be a secret (a secret-named variable, a credential file, the
  environment) and the destination is a real domain or recipient.
- **`scripts/perf_table.py`** regenerates the performance table in
  `docs/LIMITATIONS.md`; no script produced it before.
- **`scripts/holdout_eval.py`** implements pre-registration 2, and refuses to
  run with uncommitted changes under `src/`, so the code measured is the code
  committed.

- **Five rules for gaps the external corpora exposed**, each justified by its
  technique and tested on inputs written separately: `PRV004` host security
  controls disabled (critical), `EXE007` executing whatever a search finds,
  `EXF006` DNS exfiltration, `EXF007` secrets sent by email, and `EVA005`
  bytecode poisoning (critical) — a `.pyc` naming a capability its shipped
  source does not, read from raw bytes and never unmarshalled. Defanged URLs
  (`hxxps[:]//host[.]tk`) are re-fanged before matching. 93 rules.
- **Re-measured recall on the same corpus: 0.526, labelled as contaminated.**
  The rules were written after seeing the misses, so this is not an
  independent estimate and 0.316 remains the honest figure. It is still below
  the 0.70 pre-registered as "fit to block", so the advisory default stands
  under either reading. Anthropic's skills stay at 0 / 20 blocked.

### Changed

- **A persistence capability is HIGH; a persistence payload is CRITICAL.**
  `PER001` (shell profile), `PER002` (scheduled task or autostart) and `MEM001`
  (agent instruction file) blocked on the capability alone, which a daily
  report, a documented `export` line or "add this to your AGENTS.md" all have.
  They now report HIGH, and CRITICAL when what is written is itself an attack:
  a fetch piped to a shell, a decoded blob, a reverse shell, a program run
  from `/tmp`, an alias over `sudo`, or, for instruction files, text that
  removes oversight ("without asking", "always approve", "ignore previous
  instructions"). The self-authored malicious persistence cases still block.
- **An environment variable is a secret only when its name says so**, in both
  languages, through one shared definition. The Python pass treated every
  environment read as a secret source, so a skill reading its endpoint from
  `API_URL` and calling it was reported as credential exfiltration and
  blocked. Names ending in `_URL`, `_HOST`, `_NAME`, `_PATH` and similar are
  configuration; `AUTH` counts as a word, not inside `UNAUTHORIZED`, `OAUTH`
  or `AUTHOR`. A variable chosen at runtime is still treated as a secret.

- **`skillsniff scan` is advisory by default and exits 0.** Measured recall
  against externally-authored malicious skills is **0.316** — two in three are
  not blocked — so an exit code of 0 must not be read as "this skill is safe".
  Gating is now opt-in: `--fail-on`, `--strict`, or `fail_on` in a config file.
  The GitHub Action and the pre-commit hook both pass a severity explicitly, so
  installing either still gates. The 0.40 floor that triggered this was
  pre-registered and committed before the measurement ran.

### Fixed

False positives found on ClawHub's development split (`train` and
`validation`, rows ClawScan judged clean), each with a regression test and a
counterweight showing the attack shape still fires:

- `PER002` matched names, not registrations: the bare words `crontab`,
  `.service` and `.plist`, so a heading, a CSS class (`.services{…}`), an iOS
  `Info.plist` and a scanner's own table of techniques all read as
  persistence. It now requires an act of registration: `crontab` fed a file or
  stdin, a write into a cron or autostart directory, `systemctl enable`,
  `launchctl load`, `schtasks /create`, a Run key, a Git hook written.
- `PRV001` read Chromium's `--no-sandbox` and the YOLO model's `--yolo` as an
  agent's safety controls switched off. They count only when passed to an
  agent CLI. Its instruction-level phrases ("don't ask the user") now count
  only in files the agent reads as instructions, not in a prompt string a
  script sends to some other model.
- `EXF002` matched `nc` inside `sync`, `async` and `func` (no leading word
  boundary), read "use curl … with your API_KEY" in a sentence as a request,
  and treated a token in an `Authorization` header as payload. It now
  requires a command shape, and a secret carried only in a header or `-u` is
  reported at LOW, as `EXF001` already did.
- `CRE001` matched path markers as substrings, so `os\.environ` contained
  `.env` and `.Kubernetes-Encyclopedia` contained `.kube`, and a docstring
  saying "Load credentials" was a read of a credential store. Paths are now
  matched by component; prose and regular expressions are not paths; and a
  skill's own `.env` or `credentials.json` is MEDIUM, while the user's stores
  (`~/.ssh`, `~/.aws`, kubeconfig, `.netrc`, keychains) stay CRITICAL.

- `EXE001` missed `curl … | bash` written as markdown prose or inline code. Its
  regex pass skipped every raw match assuming the shell tokeniser had covered
  it, which was only true for shell files.
- `PRV003` read `chmod 644` and `chmod 755` as setuid. Its pattern matched any
  three-digit mode beginning 6 or 7. Setuid modes are still caught.
- The benchmark scanned each case's own `_bench.toml`, so a case's
  description could produce findings. No original case's expected detection
  depended on it.
- CI would have failed on the next push: mypy 2.x reports the untyped `yaml`
  import as an error. `types-PyYAML` is now a dev dependency.
- **A scan that could not finish reported `CLEAR`.** On time-budget
  exhaustion the engine broke out of its rule loop recording only a string in
  `errors`, never a coverage gap, so the report still read `coverage: HIGH`,
  `complete: true`, `gaps: []` while roughly half the security rules had never
  executed. The coverage ledger exists so an incomplete scan cannot return a
  clean verdict; an aborted rule loop was the one path around it. The abort now
  records a `time-budget-exceeded` gap and the verdict is `INCONCLUSIVE`.
  Found by `csv-summarizer` in `trailofbits/overtly-malicious-skills`, which
  pads a script with 100,000 newlines to force exactly this.

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

- **Recall measured against skills this project did not write**, with the
  methodology pre-registered and committed first so the thresholds could not
  move afterwards. 6 of 19 labelled malicious skills blocked: recall 0.316,
  Wilson 95% CI [0.154, 0.540]; 0 false blocks on the benign controls.
  `scripts/external_eval.py` now scores per-sample against publisher-supplied
  labels — read from `kurtpayne`'s own `expectations.json` rather than
  transcribed — and reports detection, a confidence interval, the per-rule
  breakdown, coverage, and every miss. `docs/EXTERNAL_VALIDATION.md` lists all
  13 misses with their technique and whether any rule could have caught them,
  and records the three corpora that could not be obtained from this session
  rather than substituting others.
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
