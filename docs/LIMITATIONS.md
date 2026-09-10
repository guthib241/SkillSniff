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
| Shell (`sh`/`bash`/`zsh`) | Quote-aware tokenising, pipeline analysis, comment stripping |
| Everything else | Pattern matching over text only |

JavaScript, TypeScript, Ruby, Go and Rust get no structural analysis. A
`child_process.exec` with an injected variable in a bundled `.js` file is caught
only if it matches a text pattern.

The Python dataflow is **intraprocedural**. A credential that crosses a function
boundary, passes through a class attribute, or is stored in a module-level
mutable is not tracked. `EXF002` provides weaker, pattern-based coverage for
those cases.

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
generalisation. Performance against skills in the wild is unmeasured. A
source-disjoint evaluation against an external corpus is the number that would
mean something, and it does not exist yet. See [BENCHMARK.md](BENCHMARK.md).

## Performance

Measured on 2026-09-09, Python 3.11.15, one core. Median of 7 runs.

| Input shape | Median | Files |
| --- | --- | --- |
| Minimal skill (1 file) | 1.8 ms | 1 |
| Typical skill (10 files, references + script) | 43 ms | 11 |
| Large skill (70 files, ~2 MB) | 1.2 s | 71 |
| Archive with 200 entries | 417 ms | 2 |
| One 1 MB line (padding / minified) | 1.7 s | 2 |
| 100 encoded regions | 5 ms | 2 |
| Whole 41-case benchmark corpus | 4.0 ms per skill | — |

Peak RSS across all of the above: ~111 MB.

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
- **Non-Python AST analysis** — not implemented
- **Attestation / signing** — not implemented

See [ROADMAP.md](ROADMAP.md), which separates IMPLEMENTED, PLANNED, EXPERIMENTAL
and RESEARCH and does not blur them.
