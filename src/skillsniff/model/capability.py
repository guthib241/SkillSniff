"""The capability model.

The product question is "what can this skill actually do?", and a capability is
the unit of that answer. Capabilities are *inferred* from evidence across five
independent sources — the description, the declared tools, the natural-language
instructions, the bundled code, and the dependency manifests — and every
inference keeps a pointer to the evidence that produced it.

Keeping the source on each observation is what makes Phase 5 possible: a
capability seen only in ``code`` but absent from ``declared`` is undeclared
access, and that comparison is only expressible because the sources are not
merged into one undifferentiated set.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from skillsniff.model.finding import Confidence, Evidence


class Capability(str, Enum):
    """What a skill can reach."""

    FS_READ = "filesystem.read"
    FS_WRITE = "filesystem.write"
    FS_DELETE = "filesystem.delete"
    NET_OUTBOUND = "network.outbound"
    NET_FETCH = "network.fetch"
    NET_LISTEN = "network.listen"
    NET_DNS = "network.dns"
    PROC_EXEC = "process.exec"
    SHELL_EXEC = "process.shell"
    CODE_EVAL = "process.eval"
    ENV_READ = "environment.read"
    ENV_WRITE = "environment.write"
    SECRET_ACCESS = "secret.access"  # noqa: S105 - a capability name, not a credential
    CREDENTIAL_HANDLING = "secret.handling"
    PKG_INSTALL = "supply.install"
    REMOTE_INSTRUCTIONS = "supply.remote-instructions"
    PERSISTENCE = "persistence.write"
    CONFIG_MODIFY = "persistence.config"
    MEMORY_WRITE = "persistence.memory"
    TOOL_USE = "tool.use"
    GIT_WRITE = "vcs.write"

    @property
    def label(self) -> str:
        return _LABELS[self]

    @property
    def is_privileged(self) -> bool:
        """Capabilities that materially widen the blast radius of a skill."""
        return self in _PRIVILEGED

    @property
    def group(self) -> str:
        return self.value.split(".", 1)[0]


_LABELS: dict[Capability, str] = {
    Capability.FS_READ: "read files",
    Capability.FS_WRITE: "write files",
    Capability.FS_DELETE: "delete files",
    Capability.NET_OUTBOUND: "send data to a remote host",
    Capability.NET_FETCH: "retrieve content from a remote host",
    Capability.NET_LISTEN: "listen on a network socket",
    Capability.NET_DNS: "perform DNS lookups",
    Capability.PROC_EXEC: "execute a subprocess",
    Capability.SHELL_EXEC: "execute a shell command",
    Capability.CODE_EVAL: "evaluate code at runtime",
    Capability.ENV_READ: "read environment variables",
    Capability.ENV_WRITE: "modify environment variables",
    Capability.SECRET_ACCESS: "access credential stores",
    Capability.CREDENTIAL_HANDLING: "handle credentials or tokens",
    Capability.PKG_INSTALL: "install packages",
    Capability.REMOTE_INSTRUCTIONS: "fetch instructions from a remote source",
    Capability.PERSISTENCE: "write persistent state",
    Capability.CONFIG_MODIFY: "modify configuration",
    Capability.MEMORY_WRITE: "write to agent memory",
    Capability.TOOL_USE: "invoke agent tools",
    Capability.GIT_WRITE: "modify version control state",
}

_PRIVILEGED = frozenset(
    {
        Capability.SHELL_EXEC,
        Capability.PROC_EXEC,
        Capability.CODE_EVAL,
        Capability.SECRET_ACCESS,
        Capability.CREDENTIAL_HANDLING,
        Capability.NET_OUTBOUND,
        Capability.NET_FETCH,
        Capability.PKG_INSTALL,
        Capability.REMOTE_INSTRUCTIONS,
        Capability.FS_DELETE,
        Capability.ENV_READ,
        Capability.PERSISTENCE,
        Capability.CONFIG_MODIFY,
        Capability.MEMORY_WRITE,
    }
)


class Source(str, Enum):
    """Where a capability observation came from.

    Ordered from "what the skill says about itself" to "what its code does",
    which is exactly the axis a mismatch is measured along.
    """

    DESCRIPTION = "description"
    DECLARED = "declared"
    INSTRUCTIONS = "instructions"
    CODE = "code"
    DEPENDENCY = "dependency"
    EXTERNAL = "external"
    OBSERVED = "observed"

    @property
    def is_claim(self) -> bool:
        """True for sources that represent the author's *claim* about the skill."""
        return self in (Source.DESCRIPTION, Source.DECLARED)


@dataclass
class Observation:
    """One piece of evidence that a skill has a capability."""

    capability: Capability
    source: Source
    confidence: Confidence
    evidence: Evidence
    detail: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "capability": self.capability.value,
            "source": self.source.value,
            "confidence": self.confidence.value,
            "detail": self.detail,
            "evidence": self.evidence.as_dict(),
        }


@dataclass
class CapabilitySurface:
    """Every capability observation for one skill, indexed for comparison."""

    observations: list[Observation] = field(default_factory=list)

    def add(self, observation: Observation) -> None:
        self.observations.append(observation)

    def extend(self, observations: Iterable[Observation]) -> None:
        self.observations.extend(observations)

    # -- projections --------------------------------------------------------

    def by_source(self, *sources: Source) -> set[Capability]:
        wanted = set(sources)
        return {o.capability for o in self.observations if o.source in wanted}

    def by_capability(self, capability: Capability) -> list[Observation]:
        return [o for o in self.observations if o.capability is capability]

    def sources_for(self, capability: Capability) -> set[Source]:
        return {o.source for o in self.observations if o.capability is capability}

    @property
    def all(self) -> set[Capability]:
        return {o.capability for o in self.observations}

    @property
    def claimed(self) -> set[Capability]:
        """Capabilities the author asserted, via description or ``allowed-tools``."""
        return self.by_source(Source.DESCRIPTION, Source.DECLARED)

    @property
    def actual(self) -> set[Capability]:
        """Capabilities evidenced by instructions, code, dependencies, or externals."""
        return self.by_source(
            Source.INSTRUCTIONS, Source.CODE, Source.DEPENDENCY, Source.EXTERNAL, Source.OBSERVED
        )

    @property
    def undeclared(self) -> set[Capability]:
        """Present in behaviour, absent from every claim."""
        return self.actual - self.claimed

    @property
    def unused(self) -> set[Capability]:
        """Claimed but never evidenced — over-broad permission requests."""
        return self.claimed - self.actual

    @property
    def privileged(self) -> set[Capability]:
        return {c for c in self.all if c.is_privileged}

    def best_confidence(self, capability: Capability) -> Confidence:
        observations = self.by_capability(capability)
        if not observations:
            return Confidence.LOW
        return min((o.confidence for o in observations), key=lambda c: c.rank)

    def as_dict(self) -> dict[str, object]:
        return {
            "capabilities": sorted(c.value for c in self.all),
            "claimed": sorted(c.value for c in self.claimed),
            "actual": sorted(c.value for c in self.actual),
            "undeclared": sorted(c.value for c in self.undeclared),
            "unused": sorted(c.value for c in self.unused),
            "privileged": sorted(c.value for c in self.privileged),
            "observations": [o.as_dict() for o in self.observations],
        }
