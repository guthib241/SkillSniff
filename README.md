# SkillSniff

**Security, trust, and capability analysis for AI agent skills.**

[![tests](https://github.com/guthib241/SkillSniff/actions/workflows/ci.yml/badge.svg)](https://github.com/guthib241/SkillSniff/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![dependencies](https://img.shields.io/badge/runtime%20dependencies-none-lightgrey)](pyproject.toml)

---

## The question this answers

> What does this skill claim to do, what can it access, what does it trust,
> what does it actually do, and has that changed since it was approved?

A skill is not documentation. Its text enters the agent's context and is read as
instruction, and its bundled scripts run with the agent's privileges: your
filesystem, your environment variables, your network. A skill that says it
formats Markdown, and also posts your `GITHUB_TOKEN` to a server, looks
identical to one that only formats Markdown — until someone reads all of it.

SkillSniff reads all of it.

```console
$ skillsniff scan ./skills/md-formatter

  md-formatter   BLOCK   Critical security findings; do not install without remediation
    risk:  security risk critical · capability exposure high

    !! EXF001  Secret value flows to a network sink
         scripts/fmt.py: value from os.environ (line 3) reaches requests.post() at line 4
         scripts/fmt.py:3  — secret source
         scripts/fmt.py:4  — network sink

     ! CON001  Capability mismatch between description and behaviour
         described as 'Formats Markdown files.' but also sends data to a remote
         host, executes a shell command, reads environment variables

    capabilities: +network.outbound +process.shell +environment.read
    (+ marks a capability the skill does not declare)
    analysed: files 2/2 · coverage HIGH
```

That EXF001 is not a pattern match. It is a dataflow observed in the Python AST,
from an environment read to an HTTP sink, through two intermediate variables.

> **Not released yet.** There is no PyPI package and no `v0.2.0` tag, so
> `pip install skillsniff` and `uses: …@v0.2.0` do not resolve. Install from
> source (below) until the first release lands. Everything else on this page
> works today.

## Get it running

**Locally, from source** — no install step, no dependencies:

```bash
git clone https://github.com/guthib241/SkillSniff && cd SkillSniff
PYTHONPATH=src python -m skillsniff scan ./examples/skills
```

Or install it properly:

```bash
pip install -e .          # from a checkout
skillsniff scan ./skills
```

**In CI** — one step, no secrets, no API key. Pin to a commit until there is a
tag:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }        # lets it diff against the base commit

- uses: guthib241/SkillSniff@main    # or a commit SHA; @v0.2.0 once released
  with:
    path: ./skills
    fail-on: high
```

It uploads SARIF to code scanning and comments the capability diff on pull
requests. Outputs `verdict`, `findings` and `critical` for downstream steps.

**As a pre-commit hook:**

```yaml
repos:
  - repo: https://github.com/guthib241/SkillSniff
    rev: main               # or a commit SHA; a tag once released
    hooks:
      - id: skillsniff      # scans only the skills your commit touched
```

**Scaffold everything at once** — config, policy and a CI workflow, pointed at
wherever your skills actually live:

```bash
skillsniff init                 # or --profile strict | advisory
```

### Already have findings? Start the gate anyway

The reason new analysers get switched off is that day one they report everything
at once. Record what exists today and enforce only what happens next:

```bash
skillsniff baseline ./skills -o skillsniff-baseline.json
skillsniff scan ./skills --baseline skillsniff-baseline.json   # exits 0
```

A baseline fingerprints findings by rule, file and evidence — **not** line
number — so reformatting a file does not resurrect everything, and moving code
does not mask anything new. Counts are respected: if two `EXE003` findings are
baselined and a third appears, the third is reported. Every report states how
many findings were suppressed, and you cannot baseline away a coverage gap.

## Install

No runtime dependencies. It runs on a bare `python:3.11` image with no install
step at all if you prefer:

```bash
git clone https://github.com/guthib241/SkillSniff && cd SkillSniff
PYTHONPATH=src python -m skillsniff scan ./path/to/skills
```

Installing PyYAML (`pip install 'skillsniff[yaml]'`) improves frontmatter
fidelity. Nothing requires it; the built-in fallback parser is tested for parity
against PyYAML on every document shape a skill can contain.

## Commands

| Command | What it does |
| --- | --- |
| `skillsniff init` | Scaffold config, policy and a CI workflow for this repo |
| `skillsniff scan PATH` | Analyse a skill, or every skill under a directory |
| `skillsniff baseline PATH` | Record today's findings so the gate enforces only new work |
| `skillsniff inspect PATH` | Full trust report: purpose, capabilities, trust graph, coverage |
| `skillsniff rules` | List the 93-rule catalogue |
| `skillsniff explain RULE` | What a rule detects, why it matters, and what it cannot see |
| `skillsniff lock PATH` | Record the skill's current capabilities, hashes and provenance |
| `skillsniff verify PATH` | Report meaningful changes since the lockfile |
| `skillsniff diff OLD NEW` | Compare two versions by *behaviour*, not text |
| `skillsniff policy check PATH --policy P` | Evaluate against policy-as-code |
| `skillsniff benchmark` | Run the evaluation corpus (source checkout only) |

Output formats: `terminal`, `json`, `sarif` (2.1.0, for GitHub code scanning),
`markdown` (for job summaries and PR comments).

Exit codes: `0` nothing at or above the threshold, `1` findings at or above it,
`2` usage error, `3` the tool itself failed. `1` and `3` are kept distinct so a
broken scanner cannot show up as a passing build.

## What it analyses

Not just `SKILL.md`. Every artifact that reaches the agent:

- **Instructions** — the body, and every referenced document under `references/`
- **Bundled code** — Python via AST (not regex), JavaScript and TypeScript via a tokeniser that knows
  strings, templates, comments and regexes from code, shell via a quote-aware tokeniser
- **Dependencies** — `requirements.txt`, `package.json`, `pyproject.toml`, and npm install hooks
- **External references** — every URL, classified by how much it can change after review
- **Archives** — inside `.zip` and `.tar.*`, recursively, in memory, never extracted
- **Encoded content** — base64, base32, hex, percent, escape, and Unicode tag characters, decoded recursively
- **Unicode** — zero-width, bidirectional overrides, tag characters, homoglyphs

### Why AST and not regex

```python
# Never pass shell=True here: it would allow command injection.
subprocess.run(["ls", target], check=False)
```

A regex scanner reports `shell=True` on that file. SkillSniff does not, because
it parses the code. The same distinction lets it report a *real* `shell=True`
that a comment does not mention, and lets it follow a credential from
`os.environ` into a request body through intermediate variables.

## Risk is not one number

The previous generation of this tool computed a single 0–100 score across
specification compliance, documentation quality, and security. That meant
excellent documentation could numerically offset a credential exfiltration path.

SkillSniff reports independent dimensions and derives a verdict by **gating**:

```
Security risk                critical   3 finding(s)
Capability exposure          high       4 finding(s)
Supply-chain risk            medium     1 finding(s)
Specification compliance     none       clean
Authoring quality            none       clean

VERDICT  BLOCK — Critical security findings; do not install without remediation
```

A critical security finding sets the verdict regardless of everything else. No
amount of quality moves it. And a scan that could not read the artifact returns
`INCONCLUSIVE`, never `CLEAR` — because "we found nothing" and "we could not
look" are different claims.

Verdicts are `BLOCK`, `REVIEW`, `CAUTION`, `CLEAR`, `INCONCLUSIVE`. Deliberately
not "safe": a static scan cannot establish safety, and wording that implies it
would be the most harmful thing this tool could do.

## Capability analysis

Capabilities are inferred *separately* from five sources — the description, the
declared `allowed-tools`, the instruction text, the bundled code, and the
dependency manifests — and then compared. That separation is what makes the
central question expressible:

```
Declared:  "Format Markdown files."
Observed:  filesystem + shell + network + environment access
           → CON001 Capability mismatch between description and behaviour
```

`skillsniff inspect` renders the whole picture, including the trust graph:

```
◆ md-formatter
├── files (3)
│   ├── · SKILL.md
│   ├── · requirements.txt
│   └── ▸ scripts/fmt.py
├── dependencies (1)
│   └── ◇ requests >=2  [mutable]  — version range '>=2' admits future releases
├── external domains (1)
│   └── ◈ telemetry.example.tk  [suspicious]  — low-reputation TLD
└── capabilities (5)
    ├── ▶ network.outbound  [suspicious]  — send data to a remote host (undeclared)
    └── ▶ process.shell     [suspicious]  — execute a shell command (undeclared)
```

## Catching change, not just badness

Most skills are fine when you install them. The question is what happens on the
next update.

```console
$ skillsniff diff v1.2.0 v1.3.0

  capabilities
    + environment.read   (privileged)
    + network.outbound   (privileged)

  external hosts
    + telemetry.example.tk

  description
    unchanged

  verdict: CLEAR → BLOCK

  NEW BEHAVIOUR IS NOT DECLARED
    the skill gained environment.read, network.outbound while its description
    and declared tools stayed the same
```

`lock` and `verify` do the same across time rather than across versions, and
grade each change: a new privileged capability is critical, a content edit is
medium, a capability that disappeared is informational.

## Coverage is reported, always

```
Files analysed        18/18
Nested archives       3
Encoded regions       4
Hidden Unicode        checked
Coverage confidence   HIGH
```

When something could not be read — an encrypted archive, a decompression bomb, a
file over the size limit, a symlink pointing outside the tree — it is named, and
the confidence drops. **SkillSniff never reports "clean" for content it could not
inspect.**

## Rule taxonomy

94 rules in 16 families. `skillsniff explain <RULE>` gives the full entry for any
of them, including what it *cannot* detect.

| | | | |
| --- | --- | --- | --- |
| `INJ` prompt injection | `EXF` exfiltration | `CRE` credentials | `EXE` execution |
| `PRV` privilege bypass | `SUP` supply chain | `MEM` memory/state | `MCP` tool & MCP abuse |
| `EVA` scanner evasion | `OBS` obfuscation | `PER` persistence | `NET` network |
| `CON` capability mismatch | `ARC` archive risk | `SPEC` specification | `QUA` authoring quality |

`SPEC` and `QUA` sit deliberately outside the security taxonomy and never
contribute to the security verdict.

## Configuration and policy

`.skillsniff.toml`, discovered by walking up from the scan target:

```toml
[skillsniff]
fail_on = "high"
ignore = ["QUA"]
exclude = ["fixtures/*"]

[skillsniff.limits]
time_budget_seconds = 30
```

Policy-as-code is separate, because "what this repository lints" and "what this
organisation permits" are different questions:

```toml
[policy]
name = "strict-ci"
max_risk = "high"
deny = ["credential_access", "remote_instructions"]
require_approval = ["shell", "external_upload"]
require_pinned_dependencies = true
require_declared_capabilities = true
min_coverage = "MEDIUM"
```

Every decision names the clause that produced it. See
[`examples/policy-strict.toml`](examples/policy-strict.toml).

## Measured results

On **SkillSniffBench**, the 56-case corpus in `src/skillsniff/bench/corpus`:

| Metric | Value |
| --- | --- |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| False-positive rate | 0.000 |
| False-negative rate | 0.000 |
| Median scan time | 3.5 ms per skill |

Reproduce with `python -m skillsniff benchmark` from a checkout.

**Read that table narrowly.** Every case in the corpus was written by this
project, alongside the rules it exercises. It is a regression suite, not
evidence of generalisation. The tool prints this caveat itself rather than
leaving it to the README.

### Against skills this project did not write

`python scripts/external_eval.py` runs the scanner over pinned public corpora
by other authors. On `anthropics/skills` (20 skills, treated as the
false-positive corpus, since nothing in it is malicious):

| Metric | Value |
| --- | --- |
| Skills blocked | 0 / 20 |
| False BLOCK rate | 0.000, Wilson 95% CI [0.000, 0.161] |
| CRITICAL findings | 0 |

That interval is what 20 samples buys. It is not a claim that the rate is
below 16%.

This evaluation is also how five false-positive defects were found. Before
them, SkillSniff returned **BLOCK on Anthropic's own published skills** — nine
CRITICAL findings, every one of them wrong — while the self-authored benchmark
above simultaneously reported a false-positive rate of 0.000. A corpus written
alongside the rules cannot contain the shapes its author did not think of.

### Recall: measured, and poor

Measured once, on skills the rules had never seen: **SkillTrustBench v1.0**,
5,516 cases with expert labels, under a protocol committed before any sample
was downloaded ([results](docs/EXTERNAL_VALIDATION.md#results-of-pre-registration-2)):

| Metric | Value |
| --- | --- |
| **Malicious recall** (blocked) | **0.271**, Wilson 95% CI [0.255, 0.288] |
| Malicious or suspicious, flagged for a human (BLOCK or REVIEW) | 0.926 |
| False BLOCK rate on normal cases | 0.040, CI [0.031, 0.050] |
| Normal cases flagged for a human | 0.739 |

**Nearly three in four malicious skills are not blocked.** The bar for "fit
to be a blocking gate" was pre-registered at 0.70, with 0.40 as the floor
below which the tool is not a gate at all, and 0.271 is below the floor. An
earlier measurement on 19 malicious skills by other authors gave 0.316, CI
[0.154, 0.540], which agrees.

So **`skillsniff scan` is advisory by default** and exits 0. Gating is opt-in
via `--fail-on`, `--strict`, or `fail_on` in a config file; the GitHub Action
and pre-commit hook pass a severity explicitly, so both still gate.

Read a block, not a silence, and read a block knowing which skills it was
measured on. **On SkillTrustBench a block was usually right**: 828 of its
893 blocks were malicious or suspicious, and it blocked none of Anthropic's
skills. **On the benchmark below it was usually wrong**: 49 of 74 blocks fell
on benign skills. **A REVIEW is weak evidence**: three in
four of SkillTrustBench's normal cases get one. Most missed malicious skills
are among them — 1,972 of the 2,084 misses were flagged REVIEW, usually for
dynamic evaluation, obfuscation or a supply-chain finding the gate does not
treat as decisive. When it is quiet, that is weak evidence of anything. This
is consistent with the published literature: *Cloak and Detonate*
([arXiv:2607.02357](https://arxiv.org/abs/2607.02357)) reports over 90%
evasion across eight scanners, and `kurtpayne/skillscan-security` was retired
in July 2026 with the conclusion that static scanning of AI skills does not
work as a security boundary.

The 19-sample corpus that produced 0.316 is now contaminated: rules were
written after seeing its misses, and re-run on it recall is 0.526 — a figure
that did not survive contact with unseen skills.

[docs/EXTERNAL_VALIDATION.md](docs/EXTERNAL_VALIDATION.md) lists **every**
missed sample with its technique, the corpora that could not be obtained, and
the defects the exercise found in SkillSniff itself.

The corpus does include 19 benign cases built to resemble attacks — security
documentation quoting `curl | bash`, red-team skills containing injection
strings, commented-out dangerous commands, `localhost` URLs, placeholder
credentials, and an API client that legitimately sends a token in an
`Authorization` header. Without those, firing on everything would score
perfectly.

### Against Cisco's skill-scanner, on the same skills: worse

Measured once, on 14 November 2026, under a protocol committed before the
data was downloaded, on the benchmark split
[Cisco AI Defense's skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)
publishes its own figures against: MaliciousSkillBench's source-disjoint test
split, 839 malicious and 545 benign skills, `SKILL.md` text only
([results](docs/EXTERNAL_VALIDATION.md#results-of-pre-registration-3)). The
Cisco rows are Cisco's published figures.

| On the same 1,384 skills | Malicious caught | Benign flagged |
| --- | --- | --- |
| SkillSniff, BLOCK | 3.0% | 9.0% |
| SkillSniff, BLOCK or REVIEW | 43.3% | 46.2% |
| Cisco skill-scanner, rules only, HIGH and above | 7.7% | 4.0% |
| Cisco skill-scanner, rules + Gemma 4 26B judge, HIGH and above | 33.7% | 6.4% |
| Cisco skill-scanner, rules + Gemma 4 26B judge, MEDIUM and above | 66.7% | 15.4% |

**On this benchmark Cisco's scanner is better in every configuration it
reports, its rules alone included, and with an LLM judge it catches far
more.** SkillSniff's verdicts barely separate the two halves of the split. It
blocked more benign skills (49) than malicious ones (25). Fifteen of those
were vendor install scripts piped to a shell, which it blocks by design.
Eighteen were a defect: `curl … | python -m json.tool`, which only
pretty-prints JSON, mistaken for running remote code. Most of the malicious
half is SkillHarm's automatically built attacks, written as instructions
rather than code, and SkillSniff blocks 1 of those 728.

One thing favours Cisco, and is stated rather than leaned on: its rules were
tuned on this dataset's development data, which SkillSniff had never seen.
One thing makes SkillSniff's figures less independent than intended: 527 of
the test skills share their opening with ClawHub development rows, 245 of
them rows this project's false-positive work scanned. Without those 527,
SkillSniff blocks 5.8% of malicious skills and 9.3% of benign ones. The
conclusion is the same.

**As a malware detector on its own, SkillSniff is not competitive.** What it
offers that this benchmark does not measure is the rest of this README: no
runtime dependencies (Cisco's scanner declares 23), no model in the loop, and
`lock`, `verify`, `diff` and `baseline` for noticing when an approved skill
changes.

## Reference skills

Four skills that pass the gate under `--strict` live in
[`examples/skills/`](examples/skills/). They show what a well-formed skill looks
like, and the repository's own CI scans them, so the tool is continuously
applied to something other than its own fixtures.

```bash
skillsniff scan ./examples/skills
skillsniff inspect ./examples/skills/threat-model-review
```

They matter for one more reason. They were written for this project's
predecessor, against a different rule set, before any current rule existed —
the only content here not authored alongside the rules that judge it. Scanning
them immediately found a real false positive: `INJ003` fired on

> A spec written **without asking** the user anything mostly restates the request.

which is advice *advocating* asking the user. The rule was conflating
concealment (hiding what was done) with permission (failing to ask). The
concealment pattern no longer matches `without asking`; instruction-level
permission bypass moved to `PRV001` behind a pattern requiring an actual
imperative. Both directions have regression tests.

One false positive from four skills is not a statistic. It is worth recording
because it is exactly what a self-authored corpus structurally cannot surface.

## Honest limits

- **A clean result is not a safety guarantee.** It means no issues were detected
  by the enabled checks. A competent attacker who knows these rules can evade
  them.
- **Static analysis only, by default.** SkillSniff reads artifacts; it never
  executes them. It cannot tell you what a skill does at runtime.
- **English-centric.** Injection and instruction detection match English
  phrasing. The same attack in another language is largely undetected.
- **Intraprocedural dataflow, two languages.** The taint analysis behind EXF001
  covers Python (from the AST) and JavaScript/TypeScript (from a tokeniser, not a
  parser), within one function's reach and one file. Ruby, Go and shell get
  weaker, pattern-based coverage.
- **No network, no model.** External references are classified structurally, not
  fetched. There is no LLM in the loop: the optional semantic and behavioural
  layers exist as tested *contracts* with no provider and no runner behind them
  (see [ROADMAP.md](docs/ROADMAP.md)).
- **Binaries are not analysed.** A bundled `.so` or `.pyc` is reported as an
  unreviewable artifact, not decompiled.
- **Trust is not transitive.** A `CLEAR` verdict says the artifact looks
  consistent. It says nothing about the author.

Full detail in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Integrations

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write    # upload SARIF
  pull-requests: write      # comment the capability diff

steps:
  - uses: actions/checkout@v4
    with: { fetch-depth: 0 }
  - uses: guthib241/SkillSniff@main             # pin a tag or SHA once released
    with:
      path: ./skills
      fail-on: high                            # critical|high|medium|low|info
      baseline: skillsniff-baseline.json       # optional
      policy: skillsniff-policy.toml           # optional
      ignore: QUA                              # optional
```

| Input | Default | |
| --- | --- | --- |
| `path` | `.` | Skill, or directory of skills |
| `fail-on` | `high` | Severity that fails the job |
| `baseline` | — | Suppress recorded findings |
| `policy` | — | Also evaluate a policy |
| `config` | — | Explicit `.skillsniff.toml` |
| `ignore` | — | Rule ids or family prefixes |
| `sarif` | `true` | Upload to code scanning |
| `comment` | `true` | Comment the capability diff on PRs |
| `version` | — | PyPI version to install; empty installs from the action's ref |

Outputs: `verdict`, `findings`, `critical`, `sarif-file`.

SARIF and the job summary are published **before** the threshold is enforced, so
a failing gate still leaves you the full report.

### Pre-commit

```yaml
repos:
  - repo: https://github.com/guthib241/SkillSniff
    rev: v0.2.0
    hooks:
      - id: skillsniff            # only the skills this commit touched
      # - id: skillsniff-all      # the whole tree, every time
```

The hook resolves each changed file up to the skill directory that owns it and
scans that skill whole — capability mismatch and the compound-risk rules are
properties of a skill, and none of them can be evaluated from a single file.

### Plain CLI

```bash
pip install -e .        # or `pip install skillsniff` once released
skillsniff scan ./skills --format sarif -o skillsniff.sarif
skillsniff scan ./skills --fail-on high
```

See [`.github/workflows/`](.github/workflows/) for what this repository runs on
itself: tests across three Python versions with and without PyYAML, a
zero-dependency import check, the benchmark, a self-scan, and a packaging job
that fails if the wheel gains a runtime dependency.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the analysis is layered
- [docs/RULES.md](docs/RULES.md) — the full rule catalogue
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — what SkillSniff defends against, and what it does not
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — every known blind spot
- [docs/BENCHMARK.md](docs/BENCHMARK.md) — corpus methodology
- [docs/EXTERNAL_VALIDATION.md](docs/EXTERNAL_VALIDATION.md) — measured against skills written by other people
- [CLAIMS.md](CLAIMS.md) — every figure in this README, and where it came from
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — config and policy reference
- [docs/ROADMAP.md](docs/ROADMAP.md) — implemented / planned / experimental / research
- [CONTRIBUTING.md](CONTRIBUTING.md) — the bar for a new rule
- [SECURITY.md](SECURITY.md) — reporting a vulnerability in SkillSniff itself

## References

- [Agent Skills specification](https://agentskills.io/specification)
- Hong, Imani & Ahmed, [*From Anatomy to Smells: An Empirical Study of SKILL.md in Agent Skills*](https://arxiv.org/abs/2607.01456) — the authoring-smell taxonomy the `QUA` family implements
- Snyk, [*ToxicSkills*](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) — 3,984 skills audited; the attack classes the security families target
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Trojan Source](https://trojansource.codes/) — the bidirectional-text attack behind `OBS002`

## License

MIT. See [LICENSE](LICENSE).
