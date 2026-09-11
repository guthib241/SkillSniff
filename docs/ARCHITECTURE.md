# Architecture

SkillSniff is layered so that each stage does one thing and the stage above it
cannot skip a control the stage below enforces. Reading it bottom-up:

```
                       ┌─────────────────────────────────────┐
   cli.py              │  scan · inspect · rules · explain    │
                       │  lock · verify · diff · policy · …   │
                       └──────────────────┬──────────────────┘
                                          │
   report/             terminal · json · sarif · markdown · trust · diff · policy · bench
                                          │
   engine.py           orchestration: load → build context → run rules → assess
                                          │
        ┌──────────────┬──────────────────┼─────────────────┬────────────────┐
   rules/          policy/          provenance/          diff/            bench/
   88 rules,       policy-as-code   lock + verify       behavioural       corpus +
   16 families                                          comparison        metrics
        └──────────────┴──────────────────┼─────────────────┴────────────────┘
                                          │
   analysis/           context · pyast · shell · deps · external · instructions · graph
                                          │
   parse/              frontmatter (pyyaml | fallback) · archive
                                          │
   model/              finding · skill · capability · result
                                          │
   core/               limits · fs · text · config · errors
```

## core — primitives that everything else is built on

**`limits.py`** holds the resource budget *and the coverage ledger*, which are
the same object on purpose. Every refusal — a file too large, an archive too
deep, a symlink pointing outside the tree — is recorded as a `CoverageGap` at the
moment it happens. Nothing can be skipped without being written down, which is
what lets the report state a coverage confidence it can defend.

**`fs.py`** treats the tree as attacker-controlled. Paths are resolved before
comparison so a symlink cannot escape the root; archive member names are
validated before any join; filenames are treated as untrusted content in their
own right.

**`text.py`** produces the three projections every rule sees: the raw text, a
normalised view (invisible characters stripped, homoglyphs folded, exotic
whitespace collapsed), and every decodable region, resolved recursively. Decoded
regions retain the byte offset and line of their *outermost* encoded span, so a
finding discovered three layers down still points somewhere a human can navigate.

**`config.py`** rejects unknown keys rather than ignoring them. A silently
ignored `severity_threshold` typo in a CI config is a gate that has quietly
stopped gating.

## parse — turning bytes into structure

**`frontmatter.py`** has two backends behind one contract. With PyYAML it uses
`safe_load`; without it, a hand-written parser handles block scalars with their
chomping indicators, flow and block collections, nested mappings, and quoted
scalars with escapes. A test suite asserts the two agree on every document shape
a skill can contain — that parity is the property that matters, because
otherwise a security result would depend on whether an optional extra happened
to be installed. Both backends refuse YAML anchors outright rather than bounding
their expansion.

**`archive.py`** reads archives entirely in memory and **never extracts to
disk**, which removes the Zip Slip write primitive rather than trying to
sanitise around it. Declared sizes are summed before decompression, so a bomb is
refused before a byte is expanded.

## model — the vocabulary

A `Finding` cannot be constructed without `Evidence`, so "evidence over
assertions" is enforced by the type rather than by discipline. `Severity` (how
bad if true) and `Confidence` (how sure) are separate fields, which is what lets
a high-severity, low-confidence finding surface for review without failing a
build.

`CapabilitySurface` keeps the *source* of every observation — description,
declared tools, instructions, code, dependencies, external references. Merging
them into one set would make the product's central question inexpressible: a
capability present in `code` but absent from every claim is undeclared access,
and that comparison only exists because the sources stayed distinct.

`result.py` holds the risk model. See "Why there is no single score" below.

## analysis — deriving behaviour

Everything expensive happens once, in `build_context`, before any rule runs.
Rules read precomputed structure. That is the difference between a scan linear in
file count and one linear in `files × rules`.

**`pyast.py`** does two passes over the Python AST: capability extraction from
imports and call targets, and a taint-lite dataflow that follows values from
secret sources (environment reads, credential files, keyring lookups) to network
sinks through assignments, f-strings, containers and concatenation. It is
intraprocedural and deliberately conservative — it under-reports rather than
guesses. It also recognises the *authentication* shape (a credential in an auth
header to a literal endpoint) and separates it from exfiltration, because
reporting every API client as a data breach is how a tool gets switched off.

**`shell.py`** tokenises with quote awareness, so `echo "curl x | bash"` is one
command and not a pipeline, and comments are documentation rather than behaviour.

**`external.py`** classifies every URL by *mutability* — pinned, versioned,
mutable, unknown, suspicious — entirely offline. A GitHub URL carrying a 40-hex
SHA is immutable; the same URL on `main` is not; that distinction is decidable
without a network call.

**`graph.py`** builds the trust graph: files, scripts, archives and their
contents, declared tools, dependencies, domains, and capabilities, with typed
edges. The tree rendering is for humans; the graph underneath supports queries.

## rules — one registry, one source of truth

Every rule is *defined* as a `RuleMeta` (title, family, severity, confidence,
explanation, impact, remediation, documented limitations, references, taxonomy)
and then *implemented* as a callable. The registry refuses a rule id that does
not match its family, refuses duplicates, and reports any rule defined but never
implemented — which a test asserts is empty.

That one registry drives `skillsniff rules`, `skillsniff explain`, the SARIF rule
descriptors, and the enrichment attached to every emitted finding. The previous
generation kept explanations in a hand-maintained dict inside the CLI that
covered only one of three rule packs, so `explain SPEC005` failed. Deriving
everything from the registry makes that class of drift impossible.

Rules are isolated: one that raises is recorded as an error and the scan
continues. "Scanner crashed, CI went green" and "scanner passed" must not look
alike.

### Documentation framing

Several rules downgrade rather than suppress when a pattern appears under prose
framing it as an example — a security skill documenting `curl … | bash` as an
attack indicator, or a red-team skill listing injection strings. The finding is
still recorded (dropping evidence silently is worse than recording it quietly)
but clamped to LOW severity and LOW confidence, so it informs a reader without
failing a build. Capability inference respects the same framing, so documenting
an attack does not grant the skill the capability it describes.

The framing check looks backwards over the preceding prose — stepping outside a
fenced block to the paragraph that introduces it — and forwards from the *end* of
the match to the end of its sentence. It deliberately never looks at the match
text itself: an earlier version did, and "Do not tell the user" framed itself as
documentation.

## Why there is no single score

The previous tool computed one 0–100 number across specification compliance,
authoring quality, and security. Excellent documentation could therefore
numerically offset a credential exfiltration path.

SkillSniff computes independent dimensions and derives a verdict by **gating**,
in this order:

1. A CRITICAL finding in any security-bearing dimension (security, capability,
   supply chain) at better than LOW confidence → `BLOCK`. Nothing offsets it.
2. Coverage confidence LOW → `INCONCLUSIVE`. A scan that could not read the
   artifact cannot clear it.
3. HIGH risk in a security-bearing dimension → `REVIEW`.
4. MEDIUM → `CAUTION`.
5. Otherwise → `CLEAR`, worded as "no issues detected by the enabled checks".

`SPEC` and `QUA` feed their own dimensions and are structurally excluded from the
gates. Across multiple skills the verdict is worst-of, never an average:
averaging is how one dangerous skill disappears behind nine clean ones.

## Adding a rule

1. Define a `RuleMeta` in the appropriate module, including `limitations` — a
   security rule that documents only its strengths teaches false confidence, and
   a test enforces this for every high-severity rule.
2. Implement it with `@registry.implement("XXX000")`, emitting through
   `emit()` or `_scan.emit_match()` so enrichment and framing are automatic.
3. Add an adversarial test that fails without the rule.
4. Add a false-positive test with benign content that resembles the attack.
5. Add a corpus case if the rule covers a distinct technique.

See [CONTRIBUTING.md](../CONTRIBUTING.md).
