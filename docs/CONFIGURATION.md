# Configuration and policy

Two separate mechanisms, because "what this repository lints" and "what this
organisation permits" are different questions with different owners.

---

## Configuration

`.skillsniff.toml` (or `skillsniff.toml`, or a `[tool.skillsniff]` table in
`pyproject.toml`), discovered by walking up from the scan target to the
filesystem root. Command-line flags always win.

```toml
[skillsniff]
# Findings at or above this severity make the run exit 1.
fail_on = "high"              # critical | high | medium | low | info

# Findings below this are hidden from human output entirely.
min_severity = "info"

# Rule ids or family prefixes. Empty select means "everything".
select = []
ignore = ["QUA"]

# Glob patterns skipped during traversal.
exclude = ["fixtures/*", "vendor/*"]

# Opt-in layers. Both default off: static analysis must stand alone.
enable_semantic = false       # not implemented; see docs/ROADMAP.md
enable_network = false        # not implemented

expand_archives = true
strict = false

[skillsniff.limits]
max_file_bytes = 5242880
max_total_bytes = 104857600
max_files = 2000
max_archive_depth = 3
max_archive_entries = 1000
max_archive_ratio = 100
max_decode_depth = 3
time_budget_seconds = 60
max_regex_input = 1048576
follow_symlinks = false
```

**Unknown keys are an error, not a warning.** A silently ignored
`severity_threshold` typo in a CI config is a gate that has quietly stopped
gating, which is the worst possible failure for this kind of tool. The same
applies to unknown values: `fail_on = "catastrophic"` fails immediately with the
valid set.

### Flags

| Flag | Effect |
| --- | --- |
| `--select RULE` | Run only these rule ids or family prefixes (repeatable, comma-separated accepted) |
| `--ignore RULE` | Suppress these (added to config, never replacing it) |
| `--exclude GLOB` | Skip paths (added to config) |
| `--fail-on SEVERITY` | Exit-code threshold |
| `--min-severity SEVERITY` | Display threshold |
| `--strict` | Fail on any finding, including low |
| `--no-archives` | Do not inspect inside archives |
| `--timeout SECONDS` | Per-skill analysis budget |
| `--max-file-size BYTES` | Per-file read limit |
| `--follow-symlinks` | Follow symlinks (off by default; they are an escape vector) |
| `--config PATH` / `--no-config` | Override or disable discovery |
| `-q` / `-v` | Quiet (findings only) / verbose (all evidence and gaps) |
| `--format` | `terminal`, `json`, `sarif`, `markdown` |
| `-o PATH` | Write to a file (disables colour) |
| `--no-color` / `--color` | Force colour off or on (`NO_COLOR` is honoured) |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Nothing at or above the failure threshold |
| `1` | Findings at or above the threshold |
| `2` | Usage error, or nothing found to scan |
| `3` | The tool itself failed |

`1` and `3` are kept distinct on purpose. "The gate caught something" and "the
gate did not run" must not look alike in CI.

### Limits and coverage

Every limit that bites is recorded as a coverage gap and reported. Tightening a
limit does not make a scan cleaner — it makes it *less confident*, and a scan
whose confidence drops to LOW returns `INCONCLUSIVE` rather than `CLEAR`.

---

## Policy

Policy is separate from configuration and is evaluated as a pure function of the
policy document and the scan result. Nothing in the policy engine reads the
filesystem, the clock, or the environment, so a decision is reproducible and
unit-testable.

```bash
skillsniff policy check ./skills --policy policy.toml
skillsniff policy validate policy.toml
```

```toml
[policy]
name = "strict-ci"
description = "No credential access, no unpinned dependencies."

# Any finding at or above this severity denies.
max_risk = "high"

# The worst verdict tolerated.
max_verdict = "CAUTION"

# Capabilities that are never permitted.
deny = ["credential_access", "remote_instructions"]

# Capabilities permitted only with human sign-off.
require_approval = ["shell", "external_upload", "package_install"]

# Explicit exceptions to deny/require_approval.
allow = []

# Findings that deny outright, by rule id or family prefix.
deny_rules = ["INJ", "EXF", "OBS003"]

# Host allow/deny. Supports "*.example.com" and ".example.com".
allow_hosts = ["api.internal.example.com"]
deny_hosts = ["*.tk"]

require_pinned_dependencies = true
require_declared_capabilities = true
allow_unpinned_external = false

# A decision made on an incompletely-analysed artifact is not a decision.
min_coverage = "MEDIUM"       # LOW | MEDIUM | HIGH
```

### Outcomes

`ALLOW`, `REVIEW`, `DENY`. Three rather than two because the realistic answer to
most capability questions is not yes or no but "a human needs to look at this",
and an engine that cannot express that forces everything into deny and then gets
disabled. `policy check` exits `0` only when every skill is `ALLOW`.

Every decision names the clause that produced it:

```
  demo   DENY
      DENY  deny = credential_access
            skill uses denied capability: secret.handling
    REVIEW  require_approval = shell
            capability needs human approval: process.shell
      DENY  require_pinned_dependencies = true
            unpinned dependencies: requests
```

### Capability groups

Shorthands accepted by `deny`, `require_approval` and `allow`. Exact capability
names (`network.outbound`) also work. An unknown token fails at **load** time,
not silently at evaluation time.

| Group | Capabilities |
| --- | --- |
| `credential_access` | `secret.access`, `secret.handling` |
| `environment_access` | `environment.read`, `environment.write` |
| `network` | `network.outbound`, `network.fetch`, `network.listen` |
| `unrestricted_network`, `external_upload` | `network.outbound` |
| `remote_fetch` | `network.fetch`, `supply.remote-instructions` |
| `execution` | `process.exec`, `process.shell`, `process.eval` |
| `shell` | `process.shell` |
| `system_write` | `filesystem.write`, `filesystem.delete`, `persistence.config` |
| `filesystem_write` / `filesystem_delete` | the corresponding capability |
| `package_install` | `supply.install` |
| `persistence` | `persistence.write`, `persistence.config`, `persistence.memory` |
| `remote_instructions` | `supply.remote-instructions` |
| `memory` | `persistence.memory` |
