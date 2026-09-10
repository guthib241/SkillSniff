"""Optional semantic analysis layer.

**Status: interface only. No provider is implemented, and none is enabled.**

The purpose of this package is to fix the *shape* of LLM-assisted analysis
before any is written, because the dangerous decisions in this design are all
made at the boundary and are very hard to change later.

Four constraints are enforced structurally rather than by convention:

1. **Static analysis never depends on this.** Nothing in ``skillsniff.engine``
   imports this package. A scan with no provider configured produces exactly the
   same findings as a scan with one, minus the advisory ones.

2. **Scanned content is never an instruction.** ``SemanticRequest`` carries
   artifact content only as data, inside an explicit untrusted envelope. The
   provider contract forbids placing it in a system or developer position.

3. **Outputs are judgments, not facts.** Every finding produced here is marked
   ``advisory=True`` and capped at MEDIUM confidence, so it can never satisfy the
   critical-finding gate in the risk model and can never fail a build alone.

4. **Nothing leaves the machine without being asked.** The default provider is
   :class:`NullProvider`, which makes no call and returns nothing.
"""

from skillsniff.semantic.provider import (
    NullProvider,
    SemanticFinding,
    SemanticProvider,
    SemanticRequest,
    SemanticTask,
    run_semantic_analysis,
    wrap_untrusted,
)

__all__ = [
    "NullProvider",
    "SemanticFinding",
    "SemanticProvider",
    "SemanticRequest",
    "SemanticTask",
    "run_semantic_analysis",
    "wrap_untrusted",
]
