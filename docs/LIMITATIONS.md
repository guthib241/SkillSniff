# Limitations

Every security tool has blind spots. A tool that documents only its strengths
teaches false confidence, which is worse than no tool. This is the complete list
of what SkillSniff does not do, as of version 0.2.0.

## The headline

**A clean result is not a safety guarantee.** It means no issues were detected by
the enabled checks, on the content that could be read. The wording throughout the
tool is chosen to say exactly that and nothing stronger.

## What it fundamentally cannot do

**It does not execute anything.** SkillSniff is a static analyser. It cannot tell
you what a skill does at runtime, what a remote endpoint returns, or what a model
will actually do when it reads the instructions. The behavioural-analysis
contract exists in `skillsniff.sandbox`, but no runner is implemented and the
default refuses; see [ROADMAP.md](ROADMAP.md) for why an approximation would be
worse than nothing.

**It cannot judge whether the procedure is correct.** A skill can be structurally
perfect, security-clean, and encode a procedure that is simply wrong.

**It cannot establish that the author is trustworthy.** Trust is not transitive.
A `CLEAR` verdict says the artifact looks internally consistent.

**It cannot resist an attacker who has read the rules.** Every detection here is
a heuristic over content the attacker controls. Novel encodings, unusual
phrasings, and semantics-preserving rewrites will evade it. The tool raises the
floor; it does not replace reading a skill before you install it.

## Language coverage

Injection, concealment, capability inference from prose, and most instruction
analysis match **English** phrasing. The same attack expressed in another
language is largely undetected. This is the single largest gap in coverage.

## Code analysis coverage

| Language | Analysis |
| --- | --- |
| Python | AST: capabilities, `shell=True`, dynamic eval, and taint-lite dataflow |
| JavaScript / TypeScript | Tokeniser, not a parser: shell execution, dynamic eval, taint-lite dataflow into network calls, credential-file reads, capabilities |
| Shell (`sh`/`bash`/`zsh`) | Quote-aware tokenising, pipeline analysis, comment stripping, clone-then-run |
| Everything else | Pattern matching over text only |

JavaScript and TypeScript (`.js .mjs .cjs .jsx .ts .mts .cts .tsx`, and
extensionless scripts with a `node`, `deno`, `bun` or `zx` shebang) are
**tokenised, not parsed**. The tokeniser knows where strings, template
literals, comments and regular expressions begin and end, so a call written
inside one is text, not code. Names are followed through assignments,
destructuring, template literals, object literals and containers, within one
file and in source order. Values are **not** followed through function calls,
across files or re-exports, or through computed properties, and types are not
understood. Every stage is linear in the file's size, and a file that exhausts
the analyser's work budget is recorded as an `analysis-truncated` coverage gap
rather than skipped silently. An analyser or rule that raises on any input is
recorded as an `analysis-error` gap, which forbids a `CLEAR` verdict.

Ruby, Go, Rust, PHP and Perl get no structural analysis. A
`system("curl … | sh")` in a bundled `.rb` file is caught only if it matches a
text pattern.

Both dataflows are **intraprocedural**. A credential that crosses a function
boundary, passes through a class attribute (other than `this.x` in
JavaScript), or is stored in a module-level mutable is not tracked. `EXF002`
provides weaker, pattern-based coverage for those cases. An environment
variable counts as a secret only when its name says so (`TOKEN`, `SECRET`,
`API_KEY`, `PASSWORD`, a `KEY` or `PASS` word…); one stored under a neutral
name is not recognised, and one whose name ends in `_URL`, `_HOST`, `_NAME`
and similar is treated as configuration.

## Binary and compiled content

SkillSniff does not disassemble. A bundled `.so`, `.pyc`, `.exe` or `.wasm` is
reported by `EVA002` as an unreviewable artifact and its contents are **not
analysed**. This is stated in the coverage section rather than passed over.

## Archives

ZIP and TAR (gzip, bzip2, xz) are inspected recursively to a depth of 3 by
default. Not supported: 7z, RAR, and any password-protected member. Encrypted
members are reported as an explicit coverage gap and drop the coverage
confidence to LOW, which forbids a `CLEAR` verdict.

## Unicode

Confusable detection uses a curated table of the Cyrillic, Greek, Armenian,
Cherokee and fullwidth homoglyphs seen in practice — **not** the complete
UTS #39 confusables set. It requires script mixing within a single word, so
genuine multilingual prose is not flagged, but a fully non-Latin evasion in a
script this table does not cover will pass.

## Decoding

Base64, base32, hex, percent, `\x`/`\u` escapes and Unicode tag characters are
decoded recursively to depth 3. Not handled: encryption of any kind, custom
encodings, compression inside a text field, and steganography. Encrypted content
is a coverage gap, not a finding — SkillSniff cannot know what is inside it.

## External references

Classification is **entirely structural and offline**. SkillSniff does not fetch
URLs, resolve DNS, follow redirects, or query package registries. It therefore
cannot tell you whether a domain is currently malicious, whether a shortener
resolves somewhere hostile, or whether a pinned commit still exists. It can only
tell you whether a reference *can change after review*, which is decidable from
its shape.

Reputation signals (paste-site lists, URL shorteners, low-reputation TLDs) come
from curated lists. A newly-registered ordinary domain looks unremarkable.

## Capability inference

Inference from natural language is approximate and carries at most MEDIUM
confidence. It over-reports where prose is ambiguous and under-reports where a
skill expresses an intent in phrasing the patterns do not recognise. Negation is
detected within the nearest clause, so "never read SSH keys" does not register
as key access — but a negation expressed across sentences will not suppress.

A `CON003` "declared but unused" finding is especially soft: static analysis
cannot see every use.

## Specification compliance

Rules are written against the Agent Skills specification as published. Where a
loader is more permissive than the specification, SkillSniff may report a
finding on a skill that works. Where a loader is stricter, it may miss one.
Compliance findings never affect the security verdict.

## Quality rules

The `QUA` family implements a taxonomy whose source paper detects 5 of its 26
smells statically and the remaining 21 with a language model. Every rule here is
deterministic, which trades recall for the ability to run on every pull request
without an API key. Each rule's `limitations` field names the proxy it uses. Some
are weak: `QUA013` (unmarked warnings) infers salience from formatting, and
`QUA014` treats any code fence as evidence of a worked example.

## Benchmark

The reported precision and recall come from a corpus written by this project
alongside the rules it exercises. It is a **regression suite**, not evidence of
generalisation. See [BENCHMARK.md](BENCHMARK.md).

A source-disjoint evaluation now exists and is the number to read instead:
[EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md). When the self-authored
benchmark last reported a false-positive rate of 0.000, the external corpus
was simultaneously producing nine CRITICAL false positives on Anthropic's own
published skills.

**Measured recall is 0.271** (775 of 2,859 malicious SkillTrustBench cases
blocked, 95% CI [0.255, 0.288]), on expert-labelled skills the rules had never
seen, measured once under a pre-registered protocol. Nearly three in four
known-malicious skills are not blocked, which is why gating is opt-in rather
than the default. Read a block, not a silence, but do not read even a block
without asking what population it was measured on. On SkillTrustBench 0.040
of normal cases were blocked and a BLOCK was worth acting on. On
MaliciousSkillBench's source-disjoint split, 0.090 of benign skills were
blocked and 49 of 74 blocks were wrong. 33 of them were `EXE001`: vendor
install scripts piped to a shell, which it blocks by design, and
`curl … | python -m json.tool`, which executes nothing and is a defect. A
REVIEW is weak evidence, since
three in four normal cases get one; and a clean result is weak evidence of
anything. Per-rule precision is still unmeasured.

**Against another scanner on the same skills, SkillSniff loses.** On the split
Cisco's skill-scanner publishes against, SkillSniff blocks 3.0% of malicious
skills at a 9.0% false-positive rate; Cisco's rules alone catch 7.7% at 4.0%,
and with an LLM judge 33.7% at 6.4%. See
[Results of pre-registration 3](EXTERNAL_VALIDATION.md#results-of-pre-registration-3).

Two earlier figures are superseded. 0.316, on 19 samples, agrees with 0.271.
0.526, on the same 19 after closing their gaps, measured a corpus that had
shaped the rules. SkillTrustBench is now spent the same way for any rule
written with its misses in view.

## Reserved documentation domains are treated as benign

`example.com`, `.example`, `.test`, `.invalid` and `localhost` cannot be real
destinations, so every exfiltration rule ignores them; otherwise documentation
full of `https://api.example.com` would be unscannable. The cost: a sample
that uses a reserved domain as its "attacker" is not reported. Three of the
`kurtpayne` adversarial cases do exactly that, and remain misses. The same
technique against a real domain is caught.

## Documentation framing

Several rules downgrade rather than suppress when surrounding prose frames a
pattern as an example: a fenced block under "Never run these", a sentence that
says "attackers will", or a markdown blockquote. A downgraded finding is
clamped to LOW confidence, which keeps it visible but stops it reaching a
blocking verdict.

The cost is direct: **a payload placed only inside a blockquote will not
block.** Quoting is the right signal to honour — a migration guide quoting a
sample system prompt is not instructing the agent — but an author who knows
this can reach for it. The finding is still printed; nothing is dropped
silently.

## Performance

Measured on 2026-11-13, Python 3.11.18, x86_64, one core, median of 7 runs.
Every row is generated and re-measured by `python scripts/perf_table.py`, so
the table can be reproduced on any machine; absolute times depend on that
machine. (The previous table, dated 2026-09-09, had no script behind it and its
inputs are not recoverable, so its rows are not comparable with these; timing
the code before and after this change on identical inputs shows no regression.)

| Input shape | Median | Files |
| --- | --- | --- |
| Minimal skill (1 file) | 3.4 ms | 1 |
| Typical skill (10 files, references + script) | 134 ms | 11 |
| Large skill (70 files, ~2 MB) | 4.9 s | 71 |
| Archive with 200 entries | 252 ms | 2 |
| One 1 MB line (padding / minified) | 1.6 s | 2 |
| 100 encoded regions | 44 ms | 2 |
| One 1 MB JavaScript file (minified) | 2.8 s | 2 |
| Script padded with 100,000 blank lines | 205 ms | 2 |
| Whole 56-case benchmark corpus | 3.4 ms per skill | — |

Peak RSS across all of the above: ~115 MB.

Cost scales with total *bytes of text*, not file count: the dominant work is
Unicode normalisation and pattern matching over each file's projections. A 1 MB
single line is the worst realistic shape, and it is also what an attacker would
choose, which is why it is measured and regression-tested rather than assumed.

Default budgets: 5 MB per file, 100 MB total, 2,000 files, 60 seconds per skill.
Hitting any of them is recorded as a coverage gap and downgrades confidence
rather than failing silently. A skill large enough to exhaust the budget will
return `INCONCLUSIVE`, which is the correct answer.

## What is *not* implemented

Named honestly, because a roadmap item described in the present tense is a lie:

- **Semantic / LLM analysis** — contract implemented and tested in
  `skillsniff.semantic`; **no provider exists**, and the default returns nothing
- **Behavioural sandbox** — contract implemented and tested in
  `skillsniff.sandbox`; **no runner exists**, and the default refuses rather
  than returning an empty report
- **Live external resolution** — deliberately absent (local-first, offline)
- **Cross-platform behavioural differences** between agent ecosystems — not modelled
- **Ruby, Go and Rust analysis** — not implemented; JavaScript and TypeScript
  are tokenised rather than parsed (see *Code analysis coverage*)
- **Attestation / signing** — not implemented

See [ROADMAP.md](ROADMAP.md), which separates IMPLEMENTED, PLANNED, EXPERIMENTAL
and RESEARCH and does not blur them.
