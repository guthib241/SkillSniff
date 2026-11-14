# Pre-registration 3: MaliciousSkillBench results, 2026-11-14

Produced once by `scripts/msb_eval.py` at commit
`de6291bb6060d980bf8f241251a128cf30c860a5`, whose `src/` tree is identical to
`a27142e`'s, between 10:39:50Z and 10:40:20Z. The protocol is in
[`docs/EXTERNAL_VALIDATION.md`](../../EXTERNAL_VALIDATION.md), *Pre-registration
3*, committed in `05e5c80` before any sample was downloaded; the results and
their reading are under *Results of pre-registration 3*. The tables there are
generated from `summary.json` by
`python scripts/msb_eval.py --render docs/results/msb-2026-11-14/summary.json`.

| File | Contents |
| --- | --- |
| `summary.json` | Every aggregate: the three operating points with Wilson intervals, the comparison with Cisco's published figures at matched false-positive rate, verdicts by label, breakdowns by held-out source and by attack category, rules firing at HIGH or above, the overlap audit, and every figure again without the overlapping identities |
| `predictions.jsonl` | One line per test identity, all 1,384: `benchmark_id`, the dataset's `label` (`1` malicious, `0` benign), `source_id`, this tool's verdict, coverage, and the verdict-bearing rules that fired at CRITICAL, HIGH and MEDIUM. Every miss at every operating point is here |
| `missed_malicious.jsonl` | The 301 malicious identities SkillSniff left CLEAR, with their attack categories |
| `false_blocks.jsonl` | The 49 benign identities SkillSniff blocked, with the rules that did it |
| `overlap_detail.json` | Added after the measurement by `msb_eval.py --overlap-detail`, which scans nothing: the 527 identities overlapping ClawHub development rows, split by whether the earlier false-positive work scanned the matching row (245) or not (282) |

**The corpus.** [`ProtectSkills/MaliciousSkillBench`](https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench)
at revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90`, the revision Cisco's
skill-scanner pins. `primary.parquet` (SHA-256 `1d638201…6a06`) and
`splits/source_disjoint.parquet` (SHA-256 `9fae37c5…d276`) matched the sizes
and digests Cisco's harness pins. No skill text is redistributed here.

**Licensing and attribution.** MaliciousSkillBench's own metadata — the
identifiers, labels, source and attack-category fields that appear in these
files — is CC-BY-4.0. Third-party skill artifacts keep their upstream terms
and are not included. Cite the benchmark as:

> Yue Wang, Yi Liu, Gelei Deng, Ying Zhang, Yuekang Li, Zhenyu Chen and Leo
> Zhang. *MaliciousSkillBench: A Comprehensive Benchmark for Malicious Agent
> Skill Detection.* arXiv:2608.19901, 2026.

**Not executed.** Each identity's text was written as a `SKILL.md` and read by
the scanner. Nothing in it was run, and no URL in it was followed.

**Reproduce.**

```console
$ pip install pyarrow            # the evaluation's dependency, not the scanner's
$ python scripts/msb_eval.py --cache ~/.cache/skillsniff-msb --out msb-results \
    --clawhub-dev train.jsonl validation.jsonl
```

The ClawHub files, for the overlap audit, are `data/train.jsonl` and
`data/validation.jsonl` from `OpenClaw/clawhub-security-signals` at
`69dcbd323c155312fb000ec89ea0b1efdf6a5757`. The harness refuses to run unless
`src/` is identical to `a27142e`'s, so reproducing it later needs a checkout
of that tree.
