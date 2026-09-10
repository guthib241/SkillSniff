# Security policy

## Reporting a vulnerability in SkillSniff

Report privately via [GitHub Security Advisories](https://github.com/guthib241/SkillSniff/security/advisories/new).
Please do not open a public issue for a vulnerability.

Include what you have: the input that triggers it, the version, and what you
observed. A reproducer is ideal but not required to make a report worth sending.

Expect an acknowledgement within a few days and an assessment within two weeks.
This is a small project; those are intentions, not a contractual SLA.

## What counts as a vulnerability in SkillSniff

SkillSniff parses attacker-controlled input, so the following are in scope:

- **A silent coverage hole.** Any input that causes content to be skipped
  *without a coverage gap being recorded*. This is the most serious class: it
  makes the tool report `CLEAR` on something it never read.
- **Path escape.** Any read outside the scan root, via symlink, archive member,
  or otherwise.
- **Any write outside the intended output path.** SkillSniff should only ever
  write files you explicitly asked it to (`-o`, a lockfile). It never extracts
  archives.
- **Resource exhaustion** that survives the budgets: a hang, unbounded memory,
  or a scan that cannot be interrupted.
- **Code execution in the scanner** from scanned content.
- **Information disclosure**: a scanned credential appearing in output, an
  absolute host path in a lockfile, or scanned content leaving the machine.
- **A crash that returns a success exit code**, or any path where a failure to
  analyse is reported as a clean result.

## What does not count

- **A missed detection (false negative).** Please report it as an issue with a
  reproducer — it is valuable and we want it — but evasion is expected of a
  heuristic scanner and is documented in
  [docs/LIMITATIONS.md](docs/LIMITATIONS.md). It is not a vulnerability in the
  tool's own security posture.
- **A false positive.** Also an issue, also wanted, also not a vulnerability.
- **The benchmark corpus containing malicious samples.** That is deliberate.
  Every credential-shaped string in it is synthetic and has never been valid.

## Security posture

Design decisions made specifically to reduce the scanner's own attack surface,
each covered by a test:

- **No subprocess execution, anywhere.** Asserted by an AST walk over the whole
  source tree. Provenance is read directly from `.git/HEAD` and `.git/config`
  rather than by invoking `git`, which would run a binary against an
  attacker-supplied directory.
- **No dynamic code execution.** No `eval`, `exec`, `pickle`, or `yaml.load`.
  Only `yaml.safe_load`, and only when PyYAML is present.
- **Archives are never extracted to disk.** They are read into memory, which
  removes the Zip Slip write primitive rather than sanitising around it.
  Asserted by test.
- **Symlinks are not followed by default**, and skipping one is recorded rather
  than silent.
- **No network access.** External references are classified structurally,
  offline. Nothing is fetched.
- **No model in the loop.** Scanned content never leaves the machine.
- **Every limit is enforced through one gate**, so no call site can forget one,
  and every refusal is recorded.
- **Credentials are redacted** in all output; a test asserts a matched secret
  never appears in full.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full model, including
residual risks.

## Supported versions

Pre-1.0. Only the latest release receives fixes.
