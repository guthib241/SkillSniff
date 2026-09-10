"""SkillSniff — security, trust, and capability analysis for AI agent skills.

The central question this tool exists to answer:

    What does this skill claim to do, what can it access, what does it trust,
    what does it actually do, and has that changed since it was approved?

SkillSniff is a *static* analyser by default. It reads skill artifacts; it
never executes them. A clean result means "no issues detected by the enabled
checks", which is not the same as "safe".
"""

__version__ = "0.2.0"

__all__ = ["__version__"]
