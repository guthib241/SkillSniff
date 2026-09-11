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
