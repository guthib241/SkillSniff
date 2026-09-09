# Threat model

Two distinct models, because SkillSniff is both a defence and an attack surface.

---

## Part 1 — Threats to the agent, which SkillSniff exists to detect

### Assets

- Credentials reachable by the agent: environment variables, `~/.ssh`, `~/.aws`,
  `.netrc`, `.npmrc`, keychains, browser credential stores
- The user's filesystem and source code
- The agent's own configuration and standing instructions (`CLAUDE.md`,
  `AGENTS.md`, MCP server configuration, settings files)
- The agent's tool grants
- The user's trust that the agent does what they asked

### Attacker positions

1. **Skill author.** Publishes a skill that is functional on the surface and
   malicious underneath. Full control of every artifact.
2. **Compromised dependency.** The skill is honest; something it pulls in is not.
   Reaches the user with no change to the reviewed repository.
3. **Compromised remote reference.** The skill fetches instructions or a script
   from a URL, and the content changes after review.
4. **Downstream maintainer.** A skill is approved at v1.0 and a later version
   adds capability under an unchanged description.
5. **Content the agent reads.** Untrusted text reaching the agent through a
   channel the skill opened, carrying an injection.

### Attack classes and coverage

| Class | Rules | Coverage |
| --- | --- | --- |
| Instruction override / role hijack | `INJ001`, `INJ002` | English phrasing, across raw, normalised and decoded projections |
| Concealment from the user | `INJ003` | English phrasing |
| Frame impersonation | `INJ004` | Outside fenced blocks |
| Payload in the description | `INJ006` | Selection-time reach, so highest severity |
| Credential store access | `CRE001` | Path + read-verb correlation |
| Committed credentials | `CRE002` | Known credential formats, placeholders excluded |
| Environment exfiltration | `EXF001`, `EXF002` | AST dataflow (Python), then patterns |
| Upload to anonymous endpoints | `EXF003`, `EXF004` | Curated host lists |
| Remote code execution | `EXE001`, `EXE002`, `EXE006` | Quote-aware pipeline analysis |
| Command injection | `EXE003` | Python AST |
| Dynamic evaluation / deserialisation | `EXE004` | Python AST |
| Safety-control bypass | `PRV001`, `PRV002`, `PRV003` | Known flags and APIs |
| Persistence | `PER001`, `PER002` | Profiles, cron, systemd, launchd, Run keys, git hooks |
| Agent-memory poisoning | `MEM001`, `MEM002` | Instruction-file writes |
| Tool/MCP configuration injection | `MCP001` | Config-path writes |
| Supply-chain drift | `SUP001`–`SUP005` | Manifests, install hooks, remote instructions |
| Obfuscation and evasion | `OBS001`–`OBS006`, `EVA001`–`EVA004` | Unicode, encodings, padding, binaries, type confusion |
| Archive-based hiding | `ARC001`–`ARC003` | Recursive in-memory inspection |
| Capability mismatch | `CON001`–`CON004` | Five-source inference and comparison |
| Compound risk | `CON010`–`CON014` | Lethal trifecta and related pairs |

### Out of scope for detection

- Attacks in languages other than English
- Attacks in compiled artifacts (reported as unanalysed, not decoded)
- Attacks that require executing the skill to observe
- Semantically-equivalent rewrites that avoid every pattern
- Malice in a remote endpoint's *current* content (never fetched)

---

## Part 2 — Threats to SkillSniff itself

SkillSniff parses attacker-controlled input. A scanner that can be made to hang,
crash, exhaust memory, write outside its working directory, or leak what it read
is worse than no scanner, because it fails in a way that looks like success.

### Attacker goal: make the scan silently incomplete

The worst outcome is a `CLEAR` verdict on an artifact the scanner did not fully
read.

**Mitigation.** Every refusal is recorded as a `CoverageGap` at the point it
occurs, and coverage confidence is derived from those gaps. Gate 2 of the risk
model returns `INCONCLUSIVE` rather than `CLEAR` when confidence is LOW. There is
no code path that skips content without writing it down.

### Attacker goal: escape the scan root

**Vectors.** Symlinks pointing outside the tree; archive members with `..`,
absolute paths, drive letters, or NUL bytes; tar symlink and device members.

**Mitigation.** Symlinks are not followed by default and skipping one is
recorded. Path safety is checked on *fully resolved* paths. Archive member names
are validated before any join, and **archives are never extracted to disk** —
they are read into memory, which removes the write primitive entirely rather than
sanitising around it. A test asserts no `extract`/`extractall` call exists
anywhere in the source.

### Attacker goal: exhaust resources

**Vectors.** Decompression bombs, deeply nested archives, thousands of members,
enormous files, deeply nested YAML, YAML alias expansion (billion laughs),
catastrophic regex backtracking, recursive decode chains.

**Mitigation.** Per-file, total-byte, file-count, archive-depth, archive-entry,
compression-ratio, decode-depth and wall-clock budgets, all enforced through a
single `Budget.allow_file` gate so no caller can forget one. ZIP expansion is
checked against *declared* sizes before decompression. YAML anchors are refused
outright rather than bounded. Regex input is capped at 1 MB per pattern.
Parametrised tests assert termination on pathological inputs.

### Attacker goal: execute code in the scanner

**Vectors.** `yaml.load` deserialisation; `pickle`; evaluating scanned content;
shelling out with attacker-controlled arguments.

**Mitigation.** Only `yaml.safe_load` is used, and only when PyYAML is present.
The scanner **never invokes a subprocess and never evaluates dynamic code** —
asserted by an AST-based test over the whole source tree, not a grep, because
the rule modules legitimately contain `subprocess` and `shell=True` as detection
patterns and a grep-based check would be suppressed and then stop checking.

For the same reason, provenance is read directly from `.git/HEAD` and
`.git/config` rather than by invoking `git`, which would run a binary against an
attacker-supplied directory that can carry its own configuration.

### Attacker goal: make the scanner leak

**Vectors.** Getting a credential printed into shared CI output; getting
absolute host paths into a committed lockfile; getting a scanned secret into an
LLM prompt.

**Mitigation.** `CRE002` redacts every matched credential and reports only a
prefix and length; a test asserts the full secret never appears in output.
Lockfiles record relative paths only, and credentials embedded in a git remote
URL are stripped before recording. No content leaves the machine: there is no
network access and no model in the loop.

### Attacker goal: poison the analysis through the analyser

If a semantic layer is ever added, scanned content must never become
system or developer instructions to it. The interface is specified to pass
artifact content as clearly-delimited untrusted data and to label every output as
a semantic judgment rather than a fact. It is **not implemented**, so this is a
design commitment rather than a shipped control.

### Residual risk

- Rule regexes are hand-written. One with catastrophic backtracking would be
  bounded by the input cap and the time budget, but would still cost the budget.
- The fallback YAML parser is bespoke. Parity tests cover the shapes a skill can
  contain; a shape outside that set could be mis-parsed.
- Coverage accounting is only as good as the code paths that report gaps. A
  future code path that skips content without recording it would reintroduce the
  worst failure mode. Reviewers should treat any new `continue` over content as
  requiring a `note_gap`.

## Reporting

Vulnerabilities in SkillSniff itself: see [SECURITY.md](../SECURITY.md).
