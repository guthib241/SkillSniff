# External validation

*Measured 11 September 2026, against SkillSniff at the commit that introduced
this document. Reproduce with `python scripts/external_eval.py`.*

The bundled benchmark (`skillsniff benchmark`) reports precision 1.000 and
recall 1.000 over 43 cases. That number is real, and it is not evidence the
tool works on anything. Every case in that corpus was written by this project
alongside the rules it exercises, so it measures self-consistency: whether
SkillSniff does what its authors intended on inputs its authors chose.

This document is the counterweight. It runs the scanner over skills written by
other people and reports what happened, including the parts that look bad.

## Pre-registration: recall against externally-authored malicious skills

**Committed 2026-09-11, before any result was computed.** The thresholds below
were written down first precisely so they cannot move once the numbers are in.
Git history is the evidence: this section landed in its own commit, and the
results section was added afterwards.

### Corpora, and what could not be obtained

Checked 2026-09-11. Availability is from this session, through its network
policy; a corpus blocked here may be perfectly public elsewhere.

| Corpus | Status | Licence | Pin |
|---|---|---|---|
| [`trailofbits/overtly-malicious-skills`](https://github.com/trailofbits/overtly-malicious-skills) | **obtainable** | **no licence file** (all rights reserved; read and scanned, never redistributed) | `4ffbf9461ef0505f9ce76a0d3694a18ec33ea531` |
| [`kurtpayne/skillscan-security`](https://github.com/kurtpayne/skillscan-security) adversarial cases | **obtainable** | Apache-2.0 | `c2a2cc4dc67d8d23221c1ab3fb7aa7c7695f5f82` |
| [`snyk-labs/toxicskills-goof`](https://github.com/snyk-labs/toxicskills-goof) | **obtainable** (already used) | no licence file | `80ce2e06f52fd384163c4bd6778676019723773c` |
| `cuhk-zhuque/SkillTrustBench` (Hugging Face) | **NOT obtainable here** | — | — |
| `OpenClaw/clawhub-security-signals` (Hugging Face) | **NOT obtainable here** | — | — |
| skillscan.sh scanner benchmark | **NOT obtainable here** | — | — |

The three unobtainable ones are blocked by this session's egress policy:
`huggingface.co` and `skillscan.sh` both return 403 to CONNECT at the proxy
(confirmed in the proxy's own `recentRelayFailures`). Nothing has been
substituted for them. The `openclaw/clawscan` harness repository itself is
obtainable and MIT-licensed, but it only *points at* the two Hugging Face
datasets, so it does not provide the samples. SkillTrustBench and
clawhub-security-signals therefore remain unmeasured, and the
`eval_holdout` split in particular is untouched.

### What counts as a detection

- **Primary metric — blocked.** Verdict `BLOCK`. This is the only verdict that
  fails a gate at the default threshold, so it is the only one that answers
  "would this have stopped the skill".
- **Secondary metric — flagged.** `BLOCK` or `REVIEW`: surfaced for a human.
  Reported separately and never as the headline.
- **`INCONCLUSIVE` is not a detection.** It means coverage was too poor to
  judge. It is counted as a miss in the primary metric and reported separately
  in the coverage table.
- **`CLEAR` and `CAUTION` are misses** for a malicious sample.

### Sample scope, declared in advance

SkillSniff discovers skills by `SKILL.md` and reports "no SKILL.md found"
otherwise. Ten of the 27 `kurtpayne` cases are bare fragments with no manifest
(`setup.sh`, `main.py`, `requirements.txt`, `package.json`), aimed at a scanner
that walks arbitrary directories. They are outside this tool's input contract.

Both figures will be published:

- **In-domain recall (primary).** Labelled malicious samples that are actual
  Agent Skills: 4 from Trail of Bits + 15 from `kurtpayne` = **19 samples**.
- **Whole-corpus recall (secondary).** All 29 labelled malicious samples,
  counting every non-discovered fragment as a miss. This is the pessimistic
  reading and it will be stated, not hidden.

Negative controls in scope: `a22_benign` and `a27_graph_benign` from
`kurtpayne`. A `BLOCK` on either is a false positive.

`toxicskills-goof` publishes a per-skill label only for its fake Vercel skill,
so it stays reported as a verdict spread and contributes no recall figure.

### Expected outcome

**A low number is expected.** Two independent sources say so:

- [arXiv:2607.02357](https://arxiv.org/abs/2607.02357), *Cloak and Detonate*
  (Ji, Xu, Li, Gao, Wei, Wang & Cheung, HKUST, July 2026): across eight
  scanners and 1,613 in-the-wild malicious skills, self-extracting-skill
  packing bypasses **every** scanner at over 90%, and structural obfuscation
  exceeds 80% on most static scanners.
- `kurtpayne/skillscan-security` was **retired on 2026-07-03** with the stated
  conclusion that "static scanning of AI skills doesn't work as a security
  boundary" — a maintainer shutting down their own shipped product after
  benchmarking it.

The Trail of Bits samples are additionally adversarial *by construction*: that
repository exists to subvert scanners, and one of its four skills attacks the
scanner's reasoning directly rather than hiding a payload.

### Interpretation rule, fixed in advance

Against in-domain labelled malicious samples, primary metric:

| Measured recall | Conclusion, committed now |
|---|---|
| **≥ 0.70** | The security rules are fit to block. Current default posture stands. |
| **0.40 – 0.69** | Fit as an advisory signal only. The README must say so next to any rule table, and the blocking default must be reconsidered. |
| **< 0.40** | **Not fit as a security gate.** The README must state this plainly in its own words, `--fail-on` should default to advisory rather than blocking, and the tool must stop being presented as something that catches malicious skills. |

### Anti-tuning commitment

No detection rule will be added, widened, or retuned in response to these
results inside this change. Doing so would convert an independent corpus into
a self-authored one and reproduce exactly the defect the rest of this document
records. Any rule gap found becomes a documented miss and, at most, a roadmap
entry.

---

## What this measures, and what it does not

**Measured.** The false-positive side. `anthropics/skills` is a public,
high-quality, externally authored collection. Nothing in it is malicious, so
every blocking finding there is a defect in SkillSniff. That makes the false
BLOCK rate a well-defined quantity, and it is the number that decides whether
anyone leaves this tool switched on.

**Not measured.** Recall, precision, and per-rule agreement. Doing that
honestly needs per-skill ground-truth labels produced independently of the
tool, against a written codebook, ideally by two labellers. No such labelled
corpus of agent skills is public, and this project has not built one. Nothing
below should be read as a detection rate.

**Sample size is small.** 29 skills across two corpora. The intervals are
wide and are reported as such. Treat every figure here as a smoke test that
found real bugs, not as a characterisation of the tool.

## The finding that matters

Before the fixes in this change, SkillSniff returned **BLOCK on
`anthropics/skills`** — nine CRITICAL findings across Anthropic's own
published skills. At the same moment, the self-authored benchmark reported a
false-positive rate of 0.000.

All nine were false positives. None of them could have been caught by the
bundled corpus, because each one depended on a way of writing documentation
that this project had not thought to write down. That is the concrete
argument for source-disjoint evaluation, and it is why this file exists.

| Rule | Count | Root cause |
|---|---|---|
| `PRV001` | 1 | "Don't ask the user **for a key**" read as a safety-control bypass. Declining to solicit a credential is the opposite of bypassing permission. |
| `PRV001` | 2 | An example system prompt quoted in a markdown **blockquote** treated as an instruction to the agent. Quotation is not assertion. |
| `EXF002` | 1 | The `SENDER` pattern matched the bare word "HTTP" in the prose *"HTTP/2 protocol error"*, then swallowed 200 characters that happened to contain a key name. |
| `MEM001` | 5 | `agents.md` matched *inside* `managed-agents.md` (`\b` treats `-` as a boundary), and `/memory.md` matched a URL path segment. Naming a file is not writing to it. |

A fifth defect was found in the same pass at HIGH rather than CRITICAL:
`CRE003` used `$` under `re.MULTILINE`, so **any prose line ending in the word
"env"** became a wholesale environment dump. It fired 13 times; 5 remain, and
those sit on real `os.environ` reads in scripts.

Each fix is a narrowing with a stated semantic basis, not a suppression. Each
has a regression test named after the skill that exposed it, in
`tests/security/test_false_positives.py`, and each is paired with a
counterweight test asserting the genuine attack shape still fires.

## Results

### anthropics/skills @ `34040c9c5685` — false-positive corpus

| | Before | After |
|---|---|---|
| Overall verdict | **BLOCK** | **REVIEW** |
| CRITICAL findings | 9 | **0** |
| HIGH findings | 63 | 56 |
| Skills blocked | 1 / 20 | **0 / 20** |

False BLOCK rate **0/20**, Wilson 95% CI **[0.000, 0.161]**. The upper bound is
what 20 samples buys; it is not a claim that the rate is below 16%.

Verdict spread after: REVIEW 11, CAUTION 7, CLEAR 2.

11 of 20 still land on REVIEW. That is not obviously wrong — these skills do
execute code, install packages, and read the environment, and REVIEW means
"a human should look", not "this is malicious". It is also not obviously
right. `SUP004` ("package installed at runtime") accounts for 27 of the 56
remaining HIGH findings, and 24 of those 27 sit in markdown rather than in
code — `pip install` 12, `npm install` 7, then `gem`, `pnpm`, `brew` and `go`.
Whether documentation telling a *developer* to install a package should carry
the same weight as a skill installing one at runtime is unresolved, and is
recorded in [ROADMAP.md](ROADMAP.md) rather than quietly tuned away.

### snyk-labs/toxicskills-goof @ `80ce2e06f52f` — malicious corpus

Snyk's published demo corpus for the ToxicSkills research. Detection was
unchanged by the false-positive work: **18 CRITICAL findings before and after,
3 skills blocked before and after.** The narrowings above cost nothing here,
which is the check that matters when loosening a rule.

The corpus README names the fake **Vercel** skill as its malicious sample: it
instructs the agent to post `uname -a` to `paste.c-net.org` under the guise of
an allow-list check. Two gaps showed up on it:

- **`paste.c-net.org` was not on the paste-host list.** An exact-match set
  cannot keep up with a class of service that is numerous and short-lived, so
  `EXF003` now also recognises a paste host structurally, by its leftmost
  label.
- **No rule covered the payload itself.** SkillSniff saw the shell execution
  but had nothing for *the output of a host-profiling command leaving the
  machine*. `EXF005` ("system reconnaissance output sent to a remote host")
  is new, and fires on the sample.

**The labelled malicious skill still receives REVIEW, not BLOCK.** `EXF003`
and `EXF005` are both HIGH/MEDIUM, and the verdict gates require a CRITICAL
finding at better than LOW confidence to block. Host fingerprinting is a
precursor rather than direct damage, and legitimate installers and crash
reporters do it, so HIGH is the honest severity. Raising it so that this one
sample turned red would be tuning the severity ladder to a demo. The gap is
reported instead.

## Known cost of the blockquote change

Treating a markdown blockquote as documentation framing means a payload placed
*only* inside a blockquote is clamped to LOW confidence. It stays visible and
is still reported — the design is downgrade, never suppress — but it will not
block. This is a deliberate trade, and an evasion an author could reach for.
It is listed in [LIMITATIONS.md](LIMITATIONS.md).

## Reproducing

```bash
python scripts/external_eval.py --json report.json
```

Corpora are pinned to the commits above, cloned read-only, and never executed.
