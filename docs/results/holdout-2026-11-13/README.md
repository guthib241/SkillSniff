# Pre-registration 2: holdout results, 2026-11-13

Produced once by `scripts/holdout_eval.py` at commit
`7d1d388f5bdc4c420e80580522d9477fb22fe48a` (its tree is identical to `3eecf1d`,
the commit carrying the rule work), between 15:41:22Z and 15:46:17Z. The
protocol is in [`docs/EXTERNAL_VALIDATION.md`](../../EXTERNAL_VALIDATION.md),
*Pre-registration 2*, committed in `4827b20` before any sample was downloaded.
The tables there are generated from `summary.json` by
`scripts/render_holdout.py`.

| File | Contents |
| --- | --- |
| `summary.json` | Every aggregate: headline metrics with Wilson intervals, confusion matrices, verdicts by label, per-source and per-risk-label breakdowns, per-split ClawHub figures |
| `skilltrustbench_predictions.jsonl` | One line per case, `{"id", "prediction"}` with the pre-registered verdict mapping, in the input format of the official evaluator (`tools/scanner_benchmark/evaluate_predictions.py` in the dataset repository) |
| `skilltrustbench_missed_malicious.jsonl` | All 2,084 malicious cases not blocked (headline set): case id, this tool's verdict, and the rules that fired at HIGH or above |
| `clawhub_missed_malicious.jsonl` | All 22 ClawHub holdout rows labelled malicious and not blocked |

**Licensing.** SkillTrustBench (`cuhk-zhuque/SkillTrustBench`, CC-BY-NC-SA-4.0)
is not redistributed here. The per-case files carry only case identifiers and
this tool's own output; the dataset's annotations appear only as aggregates.
To join them with its labels, download the dataset at the pinned revision
`ef338a55117c6039de7f408c24b3f05eedf0a6e3`. ClawHub
(`OpenClaw/clawhub-security-signals`, MIT) is pinned at
`69dcbd323c155312fb000ec89ea0b1efdf6a5757`.

**Not executed.** The official evaluator was read, not run: it is code from the
dataset repository. `holdout_eval.py` reimplements its formulas, and the
predictions file is in its input format, so anyone can run it to check.
