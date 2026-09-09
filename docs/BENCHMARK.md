# SkillSniffBench

The evaluation corpus and how to read its numbers.

```bash
python -m skillsniff benchmark            # from a source checkout
python -m skillsniff benchmark --format json -o results.json
python -m skillsniff benchmark --corpus /path/to/your/corpus
```

## The most important caveat

**Every case in this corpus was written by this project, alongside the rules it
exercises.** The reported precision and recall therefore measure whether
SkillSniff does what its authors intended on inputs its authors chose. That is a
regression suite. It is not evidence that the tool generalises.

Performance against skills in the wild is **unmeasured**. A source-disjoint
evaluation against a corpus this project did not write is the number that would
actually mean something, and it does not exist yet.

The tool prints this caveat in its own benchmark output rather than leaving it to
documentation, because a number without its caveat travels further than the
caveat does.

## Results

Measured on 2026-09-09 with SkillSniff 0.2.0, Python 3.11.15:

| Metric | Value |
| --- | --- |
| Cases | 41 |
| True positives | 27 |
| False positives | 0 |
| True negatives | 14 |
| False negatives | 0 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| False-positive rate | 0.000 |
| False-negative rate | 0.000 |
| Total time | ~0.6 s |
| Median per skill | 13.4 ms |

A perfect score on a self-authored corpus is what you would expect from a tool
whose rules and tests were developed together. Its value is as a **regression
gate**: any change that breaks a detection or introduces a false positive turns
this red.

The number that took real work was not the recall — it was the false-positive
rate. The first run of this corpus scored precision 0.794 with a **50%
false-positive rate on hard negatives**. Getting to zero required six substantive
fixes, each addressing a modelling gap rather than muting a rule:

| Problem | Fix |
| --- | --- |
| Dangerous commands in shell *comments* fired | Blank comments before pattern scanning, offsets preserved |
| Security docs quoting `curl \| bash` fired | Documentation-framing detection; downgrade, never suppress |
| Documented attacks granted the skill their capability | Capability inference made framing-aware |
| A legitimate API client tripped exfiltration | AST recognises the auth-header-to-literal-endpoint shape |
| `127.0.0.1` classified as a suspicious destination | Private and documentation hosts classified as non-destinations |
| URLs in shell comments became external references | Comment blanking applied to URL extraction |

## Corpus composition

| Group | Cases | Purpose |
| --- | --- | --- |
| `malicious/` | 27 | One case per attack technique |
| `benign/` | 4 | Ordinary, clean skills |
| `hard_negative/` | 10 | Benign skills built to resemble attacks |

The hard negatives are the point. Without them, a scanner that flags everything
scores perfect recall and looks excellent. They cover:

- a security skill documenting attack patterns inside fenced blocks
- a red-team skill whose body contains real injection strings
- a shell script whose dangerous commands are commented out
- development docs using `localhost`, `127.0.0.1` and private ranges
- API docs using `example.com` and `YOUR_API_KEY` placeholders
- an API client sending a token in an `Authorization` header
- git documentation mentioning `git push --force` and `sudo`
- a skill caching state in its own directory
- correctly hash-pinned dependencies and a commit-pinned URL
- a base64 fixture whose decoded content is inert CSV

Malicious cases span exfiltration, credential theft, prompt injection,
concealment, obfuscation (zero-width, bidi, Unicode tags, homoglyphs, base64),
execution (`curl | bash`, decode-and-run, dynamic eval, destructive delete),
privilege bypass, persistence (shell profile, cron), agent-memory writes, MCP
configuration writes, supply-chain (remote instructions, npm hooks), archives
(nested payload, Zip Slip), extension mismatch, capability mismatch, and the
lethal trifecta.

## Case format

Each case is a real skill directory plus a `_bench.toml`:

```toml
name = "exfil-env-to-network"
label = "malicious"              # malicious | benign
category = "exfiltration"
source = "internal"              # internal | external
description = "Environment secret flows into an HTTP POST body."
expect_rules = ["EXF001"]        # must fire
forbid_rules = []                # must not fire *actionably*
expect_verdict = "BLOCK"         # optional
```

## Scoring

**Detection** is the primary metric. A case is "flagged" when its verdict is
`BLOCK` or `REVIEW`. `CAUTION` and `CLEAR` are not flagged, because they do not
fail a default gate. Precision, recall, F1 and the error rates are computed over
this decision.

**Rule expectations** catch a case detected for the wrong reason:

- `expect_rules` — for a malicious case, the rule must fire *actionably*
  (MEDIUM severity or above). A downgraded note means the rule fired but would
  not stop anyone, which is not detection.
- `forbid_rules` — the rule must not produce an actionable finding. This is
  deliberately not "must not fire at all", because several rules downgrade
  rather than suppress when content is framed as documentation: a LOW,
  low-confidence note recording that a pattern is present is intended
  behaviour, since dropping evidence silently is worse than recording it
  quietly. Use `forbid_rules_entirely` for the stricter contract.

## Adding a case

1. Create a directory under the appropriate group with a complete skill.
2. Add `_bench.toml` with the label, category and expectations.
3. Run `python -m skillsniff benchmark` and confirm it behaves as declared.
4. For a new malicious technique, add a matching hard negative. A detection
   without a false-positive control is half a contribution.

## Reproducibility

The corpus is committed, the runner is deterministic, and no case depends on the
network, the clock, or the filesystem outside its own directory. The same commit
produces the same numbers.

The corpus is **not** shipped in the published wheel: installing a security tool
should not drop files containing credential-shaped strings and attack payloads
into every `site-packages` directory, where the user's own scanners will find
them. Run the benchmark from a checkout.
