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
| 94 rules | DERIVED | `python -m skillsniff rules \| tail -2`; `scripts/gen_rules_doc.py` prints `94 rules, 16 families` |
| 16 families | DERIVED | same |
| SARIF 2.1.0 | CITED | [OASIS SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) |
| Python 3.11+ | DERIVED | `requires-python = ">=3.11"` in `pyproject.toml`; CI runs 3.11, 3.12, 3.13 |
| Zero runtime dependencies | DERIVED | `dependencies = []` in `pyproject.toml`; asserted by the `package` and `no-dependencies` CI jobs |

## SkillSniffBench — the self-authored corpus

Measured 2026-11-13, SkillSniff 0.2.0, Python 3.11.18, one core. Reproduce with
`python -m skillsniff benchmark`. Timing is the median of 7 runs; counts are exact.

| Claim | Kind | Source |
|---|---|---|
| 56 cases | DERIVED | `ls src/skillsniff/bench/corpus/*/ \| wc -l` — 35 malicious, 4 benign, 17 hard negatives |
| 35 true positives | MEASURED | `python -m skillsniff benchmark` |
| 21 true negatives | MEASURED | same (4 benign + 17 hard negatives) |
| precision 1.000 | MEASURED | same |
| recall 1.000 | MEASURED | same |
| F1 1.000 | MEASURED | same |
| false-positive rate 0.000 | MEASURED | same |
| false-negative rate 0.000 | MEASURED | same |
| ~0.21 s total | MEASURED | same; 7 runs gave 189–224 ms |
| 3.5 ms median per skill | MEASURED | same; 7 runs gave 3.2–3.8 ms |

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

## Recall against labelled malicious skills

Measured 2026-09-11 against a pre-registration committed beforehand (commit
`fc7a03f`, before any result was computed). Reproduce with
`python scripts/external_eval.py`. Corpora pinned below.

| Claim | Kind | Source |
|---|---|---|
| 19 in-domain labelled malicious samples | DERIVED | 4 from Trail of Bits + 15 from `kurtpayne`, both pinned |
| 29 labelled malicious samples in total | DERIVED | adds the 10 `kurtpayne` fragments with no `SKILL.md` |
| 6 blocked | MEASURED | `python scripts/external_eval.py` |
| recall 0.316 | DERIVED | 6/19 |
| Wilson 95% CI [0.154, 0.540] | DERIVED | Wilson score interval, k=6, n=19, z=1.96 |
| whole-corpus recall 0.207, CI [0.098, 0.384] | DERIVED | 6/29, same method |
| 9 / 19 flagged (BLOCK or REVIEW) | MEASURED | same run |
| 0 false BLOCKs on 2 benign controls | MEASURED | same run |
| 0.70 / 0.40 interpretation thresholds | PRE-REGISTERED | committed in `fc7a03f` before measurement |
| 1 / 4 blocked on Trail of Bits, CI [0.046, 0.699] | MEASURED | same run |
| 5 / 15 blocked on `kurtpayne`, CI [0.152, 0.583] | MEASURED | same run |
| `trailofbits/overtly-malicious-skills` @ `4ffbf94…` | DERIVED | pinned in `scripts/external_eval.py`; no licence file |
| `kurtpayne/skillscan-security` @ `c2a2cc4…` | DERIVED | pinned likewise; Apache-2.0 |
| 224 s to scan a 100,000-line padded file before the fix; 301 ms after | MEASURED | timed on the Trail of Bits `csv-summarizer` sample, before and after commit `ddcf744` |
| 197 ms / 2.5 s / 224 s at 1,000 / 10,000 / 100,000 blank lines | MEASURED | synthetic padding series, same machine |

### After closing the gaps — contaminated, not independent

Measured 2026-11-13 on the same pinned corpora, after rules were written in
response to the misses above. **Not an estimate of performance on unseen
skills**; the independent figure is the 0.316 above.

| Claim | Kind | Source |
|---|---|---|
| 10 / 19 blocked after the gap fixes | MEASURED | `python scripts/external_eval.py` at commit `78f69d8` |
| recall 0.526 (contaminated) | DERIVED | 10/19 |
| Wilson 95% CI [0.317, 0.727] | DERIVED | k=10, n=19, z=1.96 |
| whole-corpus 0.345, CI [0.199, 0.527] (contaminated) | DERIVED | 10/29 |
| 13 / 19 flagged for a human (contaminated) | MEASURED | same run |
| 0 false BLOCKs on the 2 benign controls; 0 / 20 on `anthropics/skills` | MEASURED | same run |
| 93 rules after adding PRV004, EXE007, EXF006, EXF007, EVA005 | DERIVED | `scripts/gen_rules_doc.py` |
| 0.70 bar for "fit to block" still not met | DERIVED | 0.526 < 0.70, threshold from `fc7a03f` |

**Corpora that could not be obtained**, and are therefore unmeasured:
`cuhk-zhuque/SkillTrustBench` and `OpenClaw/clawhub-security-signals` (both on
Hugging Face) and the skillscan.sh benchmark. `huggingface.co` and
`skillscan.sh` each return 403 to CONNECT at this session's egress proxy.
Nothing was substituted for them. (That was the first measurement. Both
Hugging Face datasets became reachable afterwards and are the subject of
pre-registration 2; skillscan.sh remains unmeasured.)

## Holdout measurement — pre-registration 2

Measured once on 2026-11-13 by `python scripts/holdout_eval.py`, at commit
`7d1d388` (tree identical to `3eecf1d`), under the protocol committed in
`4827b20`. Aggregates in `docs/results/holdout-2026-11-13/summary.json`;
tables generated by `scripts/render_holdout.py`. SkillTrustBench headline
figures exclude its 4 contaminated `external_overtly_malicious_skills` cases.

| Claim | Kind | Source |
|---|---|---|
| 5,516 SkillTrustBench cases with expert labels | DERIVED | 5,520 in `ground_truth.json` at `ef338a55` minus the 4 contaminated |
| malicious recall 0.271 (775 / 2,859) | MEASURED | `summary.json`, `skilltrustbench.headline.malicious_recall` |
| Wilson 95% CI [0.255, 0.288] | DERIVED | k=775, n=2,859, z=1.96 |
| 0.926 of malicious or suspicious flagged (3,587 / 3,873) | MEASURED | `headline.non_normal_recall` |
| false BLOCK rate on normal 0.040 (65 / 1,643), CI [0.031, 0.050] | MEASURED | `headline.false_block_rate_on_normal` |
| 0.739 of normal cases flagged (1,214 / 1,643) | MEASURED | `headline.flagged_rate_on_normal` |
| 828 of 893 blocks malicious or suspicious | DERIVED | BLOCK column of `headline.verdicts_by_gold`: 775 + 53 of 775 + 53 + 65 |
| 2,084 malicious cases not blocked; 1,972 of them REVIEW | MEASURED | `headline.verdicts_by_gold.malicious`; the full list is `skilltrustbench_missed_malicious.jsonl` |
| below the 0.40 floor, so not fit as a gate | DERIVED | 0.271 < 0.40, interpretation rule committed in `4827b20` |
| ClawHub: 2 / 24 malicious blocked; 0.037 of clean blocked (233 / 6,237) | MEASURED | `summary.json`, `clawhub.combined` |
| 18 SkillTrustBench and 20 ClawHub scans raised (malformed URLs), counted as not detected | MEASURED | `verdicts_by_gold` ERROR column; cause diagnosed by re-scanning those cases after the run |

## Head-to-head on MaliciousSkillBench — pre-registration 3

Measured once on 2026-11-14 by `python scripts/msb_eval.py`, at commit
`de6291b` (`src/` identical to `a27142e`), under the protocol committed in
`05e5c80`, on `ProtectSkills/MaliciousSkillBench` at
`d4b42ce5766a6e0359c987cf59c1007cb3795a90`, split `source_disjoint`, test
members, each skill's text as its `SKILL.md`. Aggregates in
`docs/results/msb-2026-11-14/summary.json`; tables generated by
`python scripts/msb_eval.py --render docs/results/msb-2026-11-14/summary.json`.
Cisco's figures are cited from `cisco-ai-defense/skill-scanner`,
`docs/reference/measured-results.md` at `c558c42` (scanner 2.2.0), table
*Summary: current figures*, on the same split.

| Claim | Kind | Source |
|---|---|---|
| 1,384 skills: 839 malicious, 545 benign | CITED | MaliciousSkillBench card, Source-Disjoint protocol; the harness refuses to run on any other count |
| SkillSniff BLOCK: 3.0% of malicious (25 / 839), CI [2.0, 4.4] | MEASURED | `summary.json`, `all.operating_points.block.recall` |
| SkillSniff BLOCK: 9.0% of benign (49 / 545), CI [6.9, 11.7] | MEASURED | `all.operating_points.block.false_positive_rate` |
| 49 of 74 blocks benign, 25 malicious | MEASURED | `all.operating_points.block`, `fp` and `tp` |
| BLOCK or REVIEW: 43.3% of malicious (363 / 839), 46.2% of benign (252 / 545) | MEASURED | `all.operating_points.block_or_review` |
| SkillHarm: 728 malicious skills in the split, 1 blocked | MEASURED | `all.by_source`, `SRC009 SkillHarm`; verdicts in `predictions.jsonl` |
| 527 test skills overlap ClawHub development rows | MEASURED | `independence.clawhub_development_rows.same_opening` (the 41 exact matches are among them) |
| 245 of the 527 match rows the ClawHub false-positive work scanned | MEASURED | `python scripts/msb_eval.py --overlap-detail`, recorded in `docs/results/msb-2026-11-14/overlap_detail.json`; computed after the measurement, scans nothing |
| Without the 527: 5.8% of malicious, 9.3% of benign blocked | MEASURED | `excluding_overlap.operating_points.block` |
| Cisco, rules only, `balanced`, HIGH+: recall 7.7%, FPR 4.0% | CITED | Cisco `measured-results.md` at `c558c42`, *Summary: current figures* |
| Cisco, rules + Gemma 4 26B judge, `balanced`: HIGH+ 33.7% / 6.4%, MEDIUM+ 66.7% / 15.4% | CITED | same table |
| Cisco's rules tuned on MaliciousSkillBench's development data | CITED | same document, *How to read these numbers* |
| Cisco's scanner declares 23 runtime dependencies | DERIVED | `[project].dependencies` in its `pyproject.toml` at `c558c42` |
| Cisco's CLI has no lock, verify, diff or baseline command | DERIVED | subcommands registered in `skill_scanner/cli/cli.py` at `c558c42` |

## ClawHub development split (train + validation) — not a measurement

Rows bundling JavaScript, TypeScript, Python or a shebang script: 4,806
(2,589 clean, 2,196 suspicious, 21 malicious by ClawScan's label). The rules
were changed against these rows, so every figure here is development data.
Reproduced with the scripts described in `docs/EXTERNAL_VALIDATION.md`,
*Development work on ClawHub, before the holdout*.

| Claim | Kind | Source |
|---|---|---|
| 3,000 / 3,000 sampled `skill_md_content` values are a single line | MEASURED | first 3,000 rows of `data/train.jsonl` at `69dcbd32` |
| 443 / 2,589 clean rows blocked before (17.1%) | MEASURED | scan at commit `4827b20` |
| 118 / 2,589 clean rows blocked after (4.6%) | MEASURED | scan of this change |
| 291 of the 443 had a blocking finding in a bundled file | MEASURED | same scan as the 443 |
| 3 / 21 malicious rows blocked before, 0 after; 14 / 21 flagged both times | MEASURED | same two scans |

**Per-rule precision is still unmeasured.** Recall now has a number; precision
per rule does not, because that needs labels this project does not have.

## Performance

Measured 2026-11-13, Python 3.11.18, x86_64, one core, median of 7 runs, by
`python scripts/perf_table.py`, which generates every input shape. Table in
[docs/LIMITATIONS.md](docs/LIMITATIONS.md). The earlier 2026-09-09 figures had
no script behind them and are withdrawn rather than compared.

| Claim | Kind | Source |
|---|---|---|
| 3.4 ms minimal skill | MEASURED | `scripts/perf_table.py` |
| 134 ms typical skill (10 files) | MEASURED | same |
| 4.9 s large skill (70 files, ~2 MB) | MEASURED | same |
| 252 ms archive with 200 entries | MEASURED | same |
| 1.6 s for one 1 MB line | MEASURED | same |
| 44 ms for 100 encoded regions | MEASURED | same |
| 2.8 s for one 1 MB minified JavaScript file | MEASURED | same |
| 205 ms for a script padded with 100,000 blank lines | MEASURED | same |
| ~115 MB peak RSS | MEASURED | same |
| no timing regression from this change (4.94 s before, 5.05 s after, same input) | MEASURED | the large-skill shape timed against both trees |

## External research

These are other people's findings, quoted as they state them. SkillSniff does
not reproduce them and does not claim to.

| Claim | Kind | Source |
|---|---|---|
| Authoring-smell taxonomy behind the `QUA` family | CITED | Hong, Imani & Ahmed, *From Anatomy to Smells: An Empirical Study of SKILL.md in Agent Skills*, [arXiv:2607.01456](https://arxiv.org/abs/2607.01456) |
| 3,984 skills audited | CITED | Snyk, [*ToxicSkills*](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) |
| 13.4% of audited skills had at least one critical-level issue | CITED | same |
| `paste.c-net.org` as an exfiltration endpoint in a documented malicious skill | CITED | [`snyk-labs/toxicskills-goof`](https://github.com/snyk-labs/toxicskills-goof) README |
| Over 90% evasion across eight scanners via self-extracting packing | CITED | Ji, Xu, Li, Gao, Wei, Wang & Cheung, *Cloak and Detonate*, [arXiv:2607.02357](https://arxiv.org/abs/2607.02357) (HKUST, July 2026) |
| Static scanning of AI skills does not work as a security boundary | CITED | `kurtpayne/skillscan-security` README, retired 2026-07-03 |
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
