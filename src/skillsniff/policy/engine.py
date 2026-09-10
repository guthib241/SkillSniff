"""Policy evaluation.

A policy is a document; evaluating it is a pure function of that document and a
scan result. Nothing here reads the filesystem, the clock, or the environment,
so a policy decision is reproducible and can be unit-tested — which is the whole
point of writing policy as code rather than as a wiki page.

Three outcomes, deliberately: ALLOW, REVIEW, DENY. "Review" exists because the
realistic answer to most capability questions is not yes or no but "a human
needs to look at this", and a policy engine that cannot express that forces
everything into deny and then gets disabled.

Every decision carries the specific clause that produced it.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from skillsniff.core.errors import PolicyError
from skillsniff.model.capability import Capability
from skillsniff.model.finding import Severity
from skillsniff.model.result import SkillResult, Verdict


class Outcome(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"

    @property
    def rank(self) -> int:
        return {"DENY": 0, "REVIEW": 1, "ALLOW": 2}[self.value]


@dataclass(frozen=True)
class Clause:
    """One policy statement and where it came from."""

    key: str
    value: str
    outcome: Outcome
    reason: str


@dataclass
class Policy:
    name: str = "default"
    description: str = ""
    max_risk: Severity | None = None
    max_verdict: Verdict | None = None
    deny: tuple[str, ...] = ()
    require_approval: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()
    deny_rules: tuple[str, ...] = ()
    allow_hosts: tuple[str, ...] = ()
    deny_hosts: tuple[str, ...] = ()
    require_pinned_dependencies: bool = False
    require_declared_capabilities: bool = False
    min_coverage: str = "LOW"
    allow_unpinned_external: bool = True
    source: Path | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "max_risk": self.max_risk.value if self.max_risk else None,
            "max_verdict": self.max_verdict.value if self.max_verdict else None,
            "deny": list(self.deny),
            "require_approval": list(self.require_approval),
            "allow": list(self.allow),
            "deny_rules": list(self.deny_rules),
            "allow_hosts": list(self.allow_hosts),
            "deny_hosts": list(self.deny_hosts),
            "require_pinned_dependencies": self.require_pinned_dependencies,
            "require_declared_capabilities": self.require_declared_capabilities,
            "min_coverage": self.min_coverage,
        }


@dataclass
class Decision:
    skill: str
    outcome: Outcome = Outcome.ALLOW
    clauses: list[Clause] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW

    def add(self, clause: Clause) -> None:
        self.clauses.append(clause)
        if clause.outcome.rank < self.outcome.rank:
            self.outcome = clause.outcome

    def as_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill,
            "outcome": self.outcome.value,
            "allowed": self.allowed,
            "clauses": [
                {"key": c.key, "value": c.value, "outcome": c.outcome.value, "reason": c.reason}
                for c in self.clauses
            ],
        }


#: Policy shorthands, so a policy can say "credential_access" rather than
#: enumerating every capability that constitutes it.
CAPABILITY_GROUPS: dict[str, tuple[Capability, ...]] = {
    "credential_access": (Capability.SECRET_ACCESS, Capability.CREDENTIAL_HANDLING),
    "environment_access": (Capability.ENV_READ, Capability.ENV_WRITE),
    "network": (Capability.NET_OUTBOUND, Capability.NET_FETCH, Capability.NET_LISTEN),
    "unrestricted_network": (Capability.NET_OUTBOUND,),
    "external_upload": (Capability.NET_OUTBOUND,),
    "remote_fetch": (Capability.NET_FETCH, Capability.REMOTE_INSTRUCTIONS),
    "execution": (Capability.PROC_EXEC, Capability.SHELL_EXEC, Capability.CODE_EVAL),
    "shell": (Capability.SHELL_EXEC,),
    "system_write": (Capability.FS_WRITE, Capability.FS_DELETE, Capability.CONFIG_MODIFY),
    "filesystem_write": (Capability.FS_WRITE,),
    "filesystem_delete": (Capability.FS_DELETE,),
    "package_install": (Capability.PKG_INSTALL,),
    "persistence": (Capability.PERSISTENCE, Capability.CONFIG_MODIFY, Capability.MEMORY_WRITE),
    "remote_instructions": (Capability.REMOTE_INSTRUCTIONS,),
    "memory": (Capability.MEMORY_WRITE,),
}

_COVERAGE_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

_KNOWN_KEYS = {
    "name", "description", "max_risk", "max_verdict", "deny", "require_approval",
    "allow", "deny_rules", "allow_hosts", "deny_hosts",
    "require_pinned_dependencies", "require_declared_capabilities",
    "min_coverage", "allow_unpinned_external",
}


def resolve_capabilities(token: str) -> tuple[Capability, ...]:
    """Resolve a policy token to capabilities, accepting groups and exact names."""
    normalised = token.strip().lower().replace("-", "_")
    if normalised in CAPABILITY_GROUPS:
        return CAPABILITY_GROUPS[normalised]
    for capability in Capability:
        if capability.value == token.strip() or capability.value.replace(".", "_") == normalised:
            return (capability,)
    raise PolicyError(
        f"unknown capability or group {token!r}; valid groups: "
        + ", ".join(sorted(CAPABILITY_GROUPS))
    )


def load_policy(path: Path) -> Policy:
    """Load and validate a TOML policy document."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{path}: invalid TOML: {exc}") from exc

    section = data.get("policy", data)
    if not isinstance(section, dict):
        raise PolicyError(f"{path}: expected a [policy] table")

    unknown = {k.replace("-", "_") for k in section} - _KNOWN_KEYS
    if unknown:
        raise PolicyError(
            f"{path}: unknown policy key(s): {', '.join(sorted(unknown))}; "
            f"valid keys: {', '.join(sorted(_KNOWN_KEYS))}"
        )

    def string_list(key: str) -> tuple[str, ...]:
        value = section.get(key, section.get(key.replace("_", "-"), []))
        if isinstance(value, str):
            return (value,)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise PolicyError(f"{path}: {key!r} must be a list of strings")
        return tuple(value)

    policy = Policy(
        name=str(section.get("name", path.stem)),
        description=str(section.get("description", "")),
        deny=string_list("deny"),
        require_approval=string_list("require_approval"),
        allow=string_list("allow"),
        deny_rules=string_list("deny_rules"),
        allow_hosts=string_list("allow_hosts"),
        deny_hosts=string_list("deny_hosts"),
        require_pinned_dependencies=bool(section.get("require_pinned_dependencies", False)),
        require_declared_capabilities=bool(section.get("require_declared_capabilities", False)),
        min_coverage=str(section.get("min_coverage", "LOW")).upper(),
        allow_unpinned_external=bool(section.get("allow_unpinned_external", True)),
        source=path,
    )

    if "max_risk" in section:
        try:
            policy.max_risk = Severity.parse(str(section["max_risk"]))
        except ValueError as exc:
            raise PolicyError(f"{path}: {exc}") from exc
    if "max_verdict" in section:
        try:
            policy.max_verdict = Verdict(str(section["max_verdict"]).upper())
        except ValueError as exc:
            valid = ", ".join(v.value for v in Verdict)
            raise PolicyError(f"{path}: unknown max_verdict; valid: {valid}") from exc
    if policy.min_coverage not in _COVERAGE_RANK:
        raise PolicyError(f"{path}: min_coverage must be one of LOW, MEDIUM, HIGH")

    # Validate capability tokens now so a typo fails at load time rather than
    # silently never matching at evaluation time.
    for key, tokens in (("deny", policy.deny), ("require_approval", policy.require_approval), ("allow", policy.allow)):
        for token in tokens:
            try:
                resolve_capabilities(token)
            except PolicyError as exc:
                raise PolicyError(f"{path}: in {key!r}: {exc}") from exc

    return policy


def evaluate(policy: Policy, skill: SkillResult) -> Decision:
    """Evaluate ``policy`` against one skill's result."""
    decision = Decision(skill=skill.name)
    present = skill.capabilities.actual

    # -- explicit capability rules -----------------------------------------
    allowed = {c for token in policy.allow for c in resolve_capabilities(token)}

    for token in policy.deny:
        matched = sorted({c.value for c in resolve_capabilities(token) if c in present and c not in allowed})
        if matched:
            decision.add(
                Clause(
                    key="deny",
                    value=token,
                    outcome=Outcome.DENY,
                    reason=f"skill uses denied capability: {', '.join(matched)}",
                )
            )

    for token in policy.require_approval:
        matched = sorted({c.value for c in resolve_capabilities(token) if c in present and c not in allowed})
        if matched:
            decision.add(
                Clause(
                    key="require_approval",
                    value=token,
                    outcome=Outcome.REVIEW,
                    reason=f"capability needs human approval: {', '.join(matched)}",
                )
            )

    # -- rule and severity gates -------------------------------------------
    for pattern in policy.deny_rules:
        matched = sorted({f.rule_id for f in skill.findings if f.rule_id.startswith(pattern.upper())})
        if matched:
            decision.add(
                Clause(
                    key="deny_rules",
                    value=pattern,
                    outcome=Outcome.DENY,
                    reason=f"denied finding(s): {', '.join(matched)}",
                )
            )

    if policy.max_risk is not None:
        over = sorted(
            {f.rule_id for f in skill.findings if f.severity.rank < policy.max_risk.rank}
        )
        if over:
            decision.add(
                Clause(
                    key="max_risk",
                    value=policy.max_risk.value,
                    outcome=Outcome.DENY,
                    reason=f"finding(s) above the permitted severity: {', '.join(over)}",
                )
            )

    if policy.max_verdict is not None and skill.risk.verdict.rank < policy.max_verdict.rank:
        decision.add(
            Clause(
                key="max_verdict",
                value=policy.max_verdict.value,
                outcome=Outcome.DENY,
                reason=f"verdict {skill.risk.verdict.value} is worse than the permitted {policy.max_verdict.value}",
            )
        )

    # -- hosts --------------------------------------------------------------
    hosts = {r["host"] for r in skill.externals if r.get("host")}
    for host in sorted(hosts):
        if any(_host_matches(host, pattern) for pattern in policy.deny_hosts):
            decision.add(
                Clause(key="deny_hosts", value=host, outcome=Outcome.DENY, reason=f"denied host {host}")
            )
        elif policy.allow_hosts and not any(_host_matches(host, p) for p in policy.allow_hosts):
            decision.add(
                Clause(
                    key="allow_hosts",
                    value=host,
                    outcome=Outcome.REVIEW,
                    reason=f"host {host} is not on the allowlist",
                )
            )

    # -- supply chain -------------------------------------------------------
    if policy.require_pinned_dependencies:
        unpinned = sorted(
            {d["name"] for d in skill.dependencies if d.get("trust") in ("mutable", "unknown", "suspicious")}
        )
        if unpinned:
            decision.add(
                Clause(
                    key="require_pinned_dependencies",
                    value="true",
                    outcome=Outcome.DENY,
                    reason=f"unpinned dependencies: {', '.join(unpinned[:6])}",
                )
            )

    if not policy.allow_unpinned_external:
        mutable = sorted(
            {r["host"] for r in skill.externals if r.get("trust") in ("mutable", "suspicious", "unknown")}
        )
        if mutable:
            decision.add(
                Clause(
                    key="allow_unpinned_external",
                    value="false",
                    outcome=Outcome.REVIEW,
                    reason=f"unpinned external references: {', '.join(mutable[:6])}",
                )
            )

    if policy.require_declared_capabilities:
        undeclared = sorted({c.value for c in skill.capabilities.undeclared if c.is_privileged})
        if undeclared:
            decision.add(
                Clause(
                    key="require_declared_capabilities",
                    value="true",
                    outcome=Outcome.DENY,
                    reason=f"undeclared privileged capabilities: {', '.join(undeclared)}",
                )
            )

    # -- coverage -----------------------------------------------------------
    if _COVERAGE_RANK[skill.coverage.confidence] < _COVERAGE_RANK[policy.min_coverage]:
        decision.add(
            Clause(
                key="min_coverage",
                value=policy.min_coverage,
                outcome=Outcome.REVIEW,
                reason=(
                    f"analysis coverage was {skill.coverage.confidence}, below the required "
                    f"{policy.min_coverage}; the scan cannot support a decision"
                ),
            )
        )

    return decision


def _host_matches(host: str, pattern: str) -> bool:
    """Exact match, or a leading-dot / wildcard suffix match on the domain."""
    pattern = pattern.strip().lower()
    host = host.lower()
    if pattern.startswith("*."):
        pattern = pattern[1:]
    if pattern.startswith("."):
        return host == pattern[1:] or host.endswith(pattern)
    return host == pattern
