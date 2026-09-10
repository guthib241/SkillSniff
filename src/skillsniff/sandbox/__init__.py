"""Optional behavioural analysis layer.

**Status: interface only. No runner is implemented, and none is enabled.**

Static analysis cannot tell you what a skill does when it runs. Dynamic analysis
can, and would materially improve coverage of exactly the cases static analysis
is weakest on: obfuscated payloads, runtime-assembled commands, and behaviour in
languages this tool does not parse.

It is not implemented here, deliberately. A sandbox that leaks is worse than no
sandbox, because it produces a "dynamic analysis found nothing" result that
carries far more apparent authority than a static one — while the sample may have
detected the instrumentation, or escaped it. Shipping an approximation would be
the least honest thing this project could do.

So this package fixes the contract instead:

* :class:`SandboxRunner` — what a runner must provide
* :class:`Observation` / :class:`BehaviourReport` — what it must report
* :class:`CanarySet` — synthetic credentials whose *touch* is the signal
* :class:`RefusingRunner` — the default, which refuses and says why

The requirements in :data:`SANDBOX_REQUIREMENTS` are the bar any implementation
must clear before it is enabled by default.
"""

from skillsniff.sandbox.runner import (
    SANDBOX_REQUIREMENTS,
    BehaviourReport,
    CanarySet,
    Observation,
    ObservationKind,
    RefusingRunner,
    SandboxOutcome,
    SandboxRunner,
    SandboxUnavailable,
    correlate,
)

__all__ = [
    "SANDBOX_REQUIREMENTS",
    "BehaviourReport",
    "CanarySet",
    "Observation",
    "ObservationKind",
    "RefusingRunner",
    "SandboxOutcome",
    "SandboxRunner",
    "SandboxUnavailable",
    "correlate",
]
