# Claims

Every number and factual claim in the README and the `docs/` tree, with where
it comes from. A figure that is not in this file must not appear in the README:
CI enforces that (`scripts/claims_lint.py`, the `claims` job).

The point is not bookkeeping. A precise-looking number with no derivation is
the fastest way to lose a reader who checks, and this project's whole argument
is that it reports how often it is wrong. Three kinds of entry appear below:

- **MEASURED** — produced by a command in this repository. The command is given;
  run it and you get the number.
- **CITED** — from an external source, with the source and the figure as that
  source states it.
- **DERIVED** — a count of something in the repository, regenerable by the
  command given.

---

## Rule catalogue

| Claim | Kind | Source |
|---|---|---|
| 88 rules | DERIVED | `python -m skillsniff rules \| tail -2`; `scripts/gen_rules_doc.py` prints `88 rules, 16 families` |
| 16 families | DERIVED | same |
| SARIF 2.1.0 | CITED | [OASIS SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) |
| Python 3.11+ | DERIVED | `requires-python = ">=3.11"` in `pyproject.toml`; CI runs 3.11, 3.12, 3.13 |
| Zero runtime dependencies | DERIVED | `dependencies = []` in `pyproject.toml`; asserted by the `package` and `no-dependencies` CI jobs |

## SkillSniffBench — the self-authored corpus

Measured 2026-09-11, SkillSniff 0.2.0, Python 3.11.15, one core. Reproduce with
`python -m skillsniff benchmark`. Timing is the median of 7 runs; counts are exact.

| Claim | Kind | Source |
|---|---|---|
| 43 cases | DERIVED | `ls src/skillsniff/bench/corpus/*/ \| wc -l` — 28 malicious, 4 benign, 11 hard negatives |
| 28 true positives | MEASURED | `python -m skillsniff benchmark` |
| 15 true negatives | MEASURED | same (4 benign + 11 hard negatives) |
| precision 1.000 | MEASURED | same |
| recall 1.000 | MEASURED | same |
| F1 1.000 | MEASURED | same |
| false-positive rate 0.000 | MEASURED | same |
| false-negative rate 0.000 | MEASURED | same |
| ~0.22 s total | MEASURED | same; 7 runs gave 200–227 ms |
| 4.5 ms median per skill | MEASURED | same; 7 runs gave 4.1–4.6 ms |

**What these numbers do not mean.** Every case was written by this project
alongside the rules it exercises. The figures measure self-consistency, not
generalisation, and the tool prints that caveat itself. See
[docs/BENCHMARK.md](docs/BENCHMARK.md).

## External validation — corpora this project did not write

Measured 2026-09-11. Reproduce with `python scripts/external_eval.py`. Corpora
are pinned to the commits below.

| Claim | Kind | Source |
|---|---|---|
| 20 skills in `anthropics/skills` | DERIVED | corpus pinned at `34040c9c568585f6929bedeaad110ad08f079624` |
| 9 skills in `snyk-labs/toxicskills-goof` | DERIVED | corpus pinned at `80ce2e06f52fd384163c4bd6778676019723773c` |
| 0 / 20 skills blocked (after) | MEASURED | `python scripts/external_eval.py` |
| 1 / 20 skills blocked (before) | MEASURED | same harness at parent commit `0fda3d2` |
| 9 CRITICAL findings (before) | MEASURED | same |
| 0 CRITICAL findings (after) | MEASURED | same |
| false BLOCK rate 0.000 | DERIVED | 0/20 |
| Wilson 95% CI [0.000, 0.161] | DERIVED | Wilson score interval, k=0, n=20, z=1.96 |
| 18 CRITICAL findings on the malicious corpus, before and after | MEASURED | same harness, both commits |
| 3 skills blocked on the malicious corpus, before and after | MEASURED | same |
| 27 `SUP004` findings on `anthropics/skills`, 24 of them in markdown | MEASURED | same |
| 13 `CRE003` findings before, 5 after | MEASURED | same |

**Recall is unmeasured.** No independently labelled corpus of agent skills is
public and this project has not built one, so no detection rate is quoted
anywhere. See [docs/EXTERNAL_VALIDATION.md](docs/EXTERNAL_VALIDATION.md).

## Performance

Measured 2026-09-09 except where noted, Python 3.11.15, one core, median of 7
runs. Table in [docs/LIMITATIONS.md](docs/LIMITATIONS.md); each row is
regression-tested.

| Claim | Kind | Source |
|---|---|---|
| 1.8 ms minimal skill | MEASURED | `docs/LIMITATIONS.md` performance table |
| 43 ms typical skill | MEASURED | same |
| 1.2 s large skill (70 files, ~2 MB) | MEASURED | same |
| 417 ms archive with 200 entries | MEASURED | same |
| 1.7 s for one 1 MB line | MEASURED | same |
| 5 ms for 100 encoded regions | MEASURED | same |
| ~111 MB peak RSS | MEASURED | same |

## External research

These are other people's findings, quoted as they state them. SkillSniff does
not reproduce them and does not claim to.

| Claim | Kind | Source |
|---|---|---|
| Authoring-smell taxonomy behind the `QUA` family | CITED | Hong, Imani & Ahmed, *From Anatomy to Smells: An Empirical Study of SKILL.md in Agent Skills*, [arXiv:2607.01456](https://arxiv.org/abs/2607.01456) |
| 3,984 skills audited | CITED | Snyk, [*ToxicSkills*](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) |
| 13.4% of audited skills had at least one critical-level issue | CITED | same |
| `paste.c-net.org` as an exfiltration endpoint in a documented malicious skill | CITED | [`snyk-labs/toxicskills-goof`](https://github.com/snyk-labs/toxicskills-goof) README |
| Lethal trifecta (private data + untrusted content + egress) | CITED | Willison, [*The lethal trifecta*](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) |
| OWASP LLM taxonomy tags on rules | CITED | [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| CWE identifiers on rules | CITED | [CWE](https://cwe.mitre.org/) |
| Agent Skills specification, `SPEC` family | CITED | [agentskills.io/specification](https://agentskills.io/specification) |

## Claims deliberately not made

- **No single score or letter grade.** The previous generation of this tool
  computed one 0–100 number with penalty weights and grade thresholds that had
  no external basis. It is gone; verdicts come from gating rules. See
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- **No "safe", "clean", or "smell-free".** A static scan cannot establish
  safety. `CLEAR` means no issue was detected by the enabled checks, and the
  tool says so in those words.
- **No per-rule precision.** Measuring it needs labels this project does not
  have. Rules carry a `limitations` field stating what each cannot detect
  instead.
- **Not "production ready".** The tool is tested and its integrations are
  exercised in CI, but it has no released version and no adoption evidence.
