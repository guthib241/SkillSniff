"""Exception hierarchy.

Every error SkillSniff raises deliberately derives from :class:`SkillSniffError`
so the CLI can distinguish "the tool failed" from "the tool found something",
which are different exit codes and mean very different things to a CI gate.
"""

from __future__ import annotations


class SkillSniffError(Exception):
    """Base class for every error raised by SkillSniff itself."""


class UsageError(SkillSniffError):
    """The user asked for something that does not make sense."""


class ConfigError(SkillSniffError):
    """A configuration file is malformed or contains an unknown key."""


class PolicyError(SkillSniffError):
    """A policy document is malformed."""


class ParseError(SkillSniffError):
    """An artifact could not be parsed.

    Never fatal to a scan: an unparseable file is recorded as reduced analysis
    coverage rather than being silently skipped. Silently skipping is how a
    scanner ends up reporting "clean" on something it never read.
    """


class BudgetExceeded(SkillSniffError):
    """A resource limit was hit (size, depth, time, or file count).

    This is a *coverage* signal, not a crash. The scan continues and the
    result records that some content was not inspected.
    """


class UnsafePathError(SkillSniffError):
    """A path escapes its intended root, or is otherwise refused."""
