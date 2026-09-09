"""The behavioural-analysis contract.

Nothing here executes anything. The only concrete runner refuses.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

from skillsniff.model.capability import Capability, CapabilitySurface
from skillsniff.model.finding import Confidence, Evidence, Finding, Severity

#: The bar an implementation must clear before it may be enabled by default.
#: Written down so that "we added a sandbox" cannot quietly mean something
#: weaker than this.
SANDBOX_REQUIREMENTS: tuple[str, ...] = (
    "Execution happens in a disposable environment that is destroyed after the "
    "run, never on the host and never in a container sharing the host network "
    "namespace.",
    "No credential, token, or file belonging to the user is reachable from "
    "inside. Only synthetic canaries are present.",
    "Network egress is denied by default and observed at the boundary, so a "
    "connection attempt is recorded even though it fails.",
    "CPU, memory, wall-clock, process-count and disk limits are enforced by the "
    "environment, not by the observed process.",
    "The absence of an observation is reported as 'not observed', never as "
    "'does not happen'. A sample that detects instrumentation and stays quiet "
    "must not produce a clean result.",
    "Observations are attributed to the artifact that produced them, or marked "
    "unattributed.",
    "A failure to establish the sandbox is an error, never a clean result.",
)


class SandboxUnavailable(RuntimeError):
    """No sandbox is configured, or the configured one could not be established.

    Deliberately an error. A behavioural analysis that could not run must never
    be reported as a behavioural analysis that found nothing.
    """


class ObservationKind(str, Enum):
    FILE_READ = "file.read"
    FILE_WRITE = "file.write"
    FILE_DELETE = "file.delete"
    NETWORK_CONNECT = "network.connect"
    NETWORK_SEND = "network.send"
    DNS_QUERY = "dns.query"
    PROCESS_SPAWN = "process.spawn"
    ENV_READ = "environment.read"
    CANARY_TOUCHED = "canary.touched"
    TOOL_INVOKED = "tool.invoked"

    @property
    def capability(self) -> Capability | None:
        return {
            ObservationKind.FILE_READ: Capability.FS_READ,
            ObservationKind.FILE_WRITE: Capability.FS_WRITE,
            ObservationKind.FILE_DELETE: Capability.FS_DELETE,
            ObservationKind.NETWORK_CONNECT: Capability.NET_FETCH,
            ObservationKind.NETWORK_SEND: Capability.NET_OUTBOUND,
            ObservationKind.DNS_QUERY: Capability.NET_DNS,
            ObservationKind.PROCESS_SPAWN: Capability.PROC_EXEC,
            ObservationKind.ENV_READ: Capability.ENV_READ,
            ObservationKind.CANARY_TOUCHED: Capability.SECRET_ACCESS,
            ObservationKind.TOOL_INVOKED: Capability.TOOL_USE,
        }.get(self)


class SandboxOutcome(str, Enum):
    COMPLETED = "completed"
    TIMED_OUT = "timed-out"
    CRASHED = "crashed"
    REFUSED = "refused"
    UNAVAILABLE = "unavailable"

    @property
    def is_conclusive(self) -> bool:
        """Only a completed run says anything about what was *not* observed."""
        return self is SandboxOutcome.COMPLETED


@dataclass(frozen=True)
class Observation:
    """One thing the skill did."""

    kind: ObservationKind
    target: str
    detail: str = ""
    attributed_to: str = ""
    timestamp_ms: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "target": self.target,
            "detail": self.detail,
            "attributed_to": self.attributed_to or "unattributed",
            "timestamp_ms": self.timestamp_ms,
        }


@dataclass
class CanarySet:
    """Synthetic credentials planted where real ones would live.

    The value is never valid anywhere. The signal is that something *read* it,
    which is unambiguous in a way that static credential-path matching is not: a
    skill that touches ``~/.aws/credentials`` inside the sandbox is not
    documenting the path.
    """

    values: dict[str, str] = field(default_factory=dict)

    @classmethod
    def generate(cls, seed_paths: Iterable[str] | None = None) -> CanarySet:
        paths = list(
            seed_paths
            or (
                "~/.aws/credentials",
                "~/.ssh/id_rsa",
                "~/.netrc",
                "~/.npmrc",
                "ENV:GITHUB_TOKEN",
                "ENV:OPENAI_API_KEY",
            )
        )
        return cls(
            values={
                path: f"skillsniff-canary-{secrets.token_hex(16)}" for path in path_list(paths)
            }
        )

    def identify(self, observed: str) -> str | None:
        """Which canary, if any, this observed value corresponds to."""
        for path, value in self.values.items():
            if value and value in observed:
                return path
        return None

    @property
    def fingerprints(self) -> dict[str, str]:
        """Hashes, so a report can be shared without carrying the values."""
        return {
            path: hashlib.sha256(value.encode()).hexdigest()[:16]
            for path, value in self.values.items()
        }


def path_list(paths: Iterable[str]) -> list[str]:
    return [str(p) for p in paths]


@dataclass
class BehaviourReport:
    """What a run observed, and — as importantly — what it could not."""

    outcome: SandboxOutcome
    observations: list[Observation] = field(default_factory=list)
    canaries_touched: list[str] = field(default_factory=list)
    duration_ms: int = 0
    #: Why this run cannot support a negative conclusion, if it cannot.
    caveats: list[str] = field(default_factory=list)
    runner: str = ""

    @property
    def supports_negative_conclusion(self) -> bool:
        """Whether 'not observed' means anything here.

        A timed-out or crashed run observed a prefix of the behaviour. Saying
        "no network access was observed" about such a run would be false in
        exactly the way that matters.
        """
        return self.outcome.is_conclusive and not self.caveats

    @property
    def observed_capabilities(self) -> set[Capability]:
        return {
            capability
            for observation in self.observations
            if (capability := observation.kind.capability) is not None
        }

    def as_dict(self) -> dict[str, object]:
        return {
            "runner": self.runner,
            "outcome": self.outcome.value,
            "duration_ms": self.duration_ms,
            "supports_negative_conclusion": self.supports_negative_conclusion,
            "observed_capabilities": sorted(c.value for c in self.observed_capabilities),
            "canaries_touched": list(self.canaries_touched),
            "observations": [o.as_dict() for o in self.observations],
            "caveats": list(self.caveats),
        }


@runtime_checkable
class SandboxRunner(Protocol):
    """What an implementation must provide.

    See :data:`SANDBOX_REQUIREMENTS` for the properties it must have.
    """

    name: str

    def run(self, skill_path: Path, canaries: CanarySet, timeout_seconds: float) -> BehaviourReport: ...


class RefusingRunner:
    """The default runner. Refuses, and says why.

    Returning an empty :class:`BehaviourReport` would be far worse: callers would
    read "no observations" as "nothing happened".
    """

    name = "refusing"

    def run(self, skill_path: Path, canaries: CanarySet, timeout_seconds: float) -> BehaviourReport:
        del skill_path, canaries, timeout_seconds
        raise SandboxUnavailable(
            "no behavioural sandbox is configured. SkillSniff ships no sandbox "
            "implementation: an unsafe approximation would produce results that look "
            "authoritative and are not. See docs/ROADMAP.md."
        )


def correlate(
    report: BehaviourReport,
    surface: CapabilitySurface,
    skill: str,
) -> list[Finding]:
    """Compare observed behaviour against the statically-inferred surface.

    Two directions, and only one of them is sound:

    *Observed but not inferred* is a real finding — the static analysis missed
    something, which is exactly what dynamic analysis is for.

    *Inferred but not observed* is **not** reported as a false positive. The code
    path may simply not have been reached in this run, and treating "not
    exercised" as "not present" is how dynamic analysis talks people out of true
    findings.
    """
    if not report.supports_negative_conclusion and not report.observations:
        return []

    findings: list[Finding] = []
    static = surface.all
    for capability in sorted(report.observed_capabilities - static, key=lambda c: c.value):
        supporting = [o for o in report.observations if o.kind.capability is capability]
        findings.append(
            Finding(
                rule_id="DYN001",
                title="Behaviour observed that static analysis did not predict",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                skill=skill,
                family="CON",
                message=(
                    f"the sandbox observed {capability.label}, which no static source "
                    "accounted for"
                ),
                evidence=[
                    Evidence(
                        path=o.attributed_to or "(unattributed)",
                        excerpt=f"{o.kind.value}: {o.target}"[:200],
                        note=f"observed by the {report.runner} sandbox",
                    )
                    for o in supporting[:3]
                ],
                explanation=(
                    "Dynamic analysis saw the skill do something the static analysis did "
                    "not infer from its content."
                ),
                impact=(
                    "The skill's real capability surface is wider than its artifacts "
                    "suggest, which usually means the behaviour is obfuscated or "
                    "assembled at runtime."
                ),
                remediation="Establish what produced this behaviour before using the skill.",
                advisory=True,
            )
        )

    for path in report.canaries_touched:
        findings.append(
            Finding(
                rule_id="DYN002",
                title="Synthetic credential was read at runtime",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                skill=skill,
                family="CRE",
                message=f"the skill read the canary planted at {path}",
                evidence=[
                    Evidence(
                        path=path,
                        excerpt="synthetic canary credential",
                        note=f"observed by the {report.runner} sandbox; the value was never valid",
                    )
                ],
                explanation=(
                    "A synthetic credential planted where a real one would live was read "
                    "during execution."
                ),
                impact=(
                    "On a real machine this read would have returned the user's actual "
                    "credential. Unlike a static path match, this is the skill actually "
                    "reading it."
                ),
                remediation="Do not run this skill. Establish why it reads credential stores.",
                advisory=True,
            )
        )

    # Deliberately absent: any finding of the form "declared X but never did X".
    del static
    return findings
