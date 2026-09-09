"""Configuration loading.

Precedence, highest first: command-line flags, then the config file, then
built-in defaults. A config file is discovered by walking up from the scan
target to the filesystem root, so a repository-level ``.skillsniff.toml``
applies to every skill inside it without being passed on every invocation.

Unknown keys are an error rather than a warning. A silently-ignored
``severity_threshold`` typo in a CI config is a gate that has quietly stopped
gating, which is the worst possible failure for this kind of tool.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from skillsniff.core.errors import ConfigError
from skillsniff.core.fs import DEFAULT_EXCLUDES
from skillsniff.core.limits import Limits
from skillsniff.model.finding import Severity

CONFIG_FILENAMES = (".skillsniff.toml", "skillsniff.toml")
PYPROJECT = "pyproject.toml"


@dataclass
class Config:
    """Resolved settings for one run."""

    #: Rule ids or family prefixes to run. Empty means "everything enabled".
    select: tuple[str, ...] = ()
    #: Rule ids or family prefixes to suppress.
    ignore: tuple[str, ...] = ()
    #: Findings below this severity are reported but never fail the run.
    fail_on: Severity = Severity.HIGH
    #: Findings below this are hidden from human output entirely.
    min_severity: Severity = Severity.INFO
    exclude: tuple[str, ...] = DEFAULT_EXCLUDES
    limits: Limits = field(default_factory=Limits)
    #: Opt-in layers. Both default off: static analysis must stand alone.
    enable_semantic: bool = False
    enable_network: bool = False
    expand_archives: bool = True
    #: Treat every finding at or above ``fail_on`` as fatal, and warnings too.
    strict: bool = False
    baseline: Path | None = None
    policy: Path | None = None
    source: Path | None = None

    def is_enabled(self, rule_id: str) -> bool:
        """Whether ``rule_id`` should run, honouring select/ignore prefixes."""
        rule_id = rule_id.upper()
        if self.ignore and _matches(rule_id, self.ignore):
            return False
        if self.select:
            return _matches(rule_id, self.select)
        return True


def _matches(rule_id: str, patterns: tuple[str, ...]) -> bool:
    return any(rule_id == p.upper() or rule_id.startswith(p.upper()) for p in patterns)


_SEVERITY_KEYS = {"fail_on", "min_severity"}
_PATH_KEYS = {"baseline", "policy"}
_TUPLE_KEYS = {"select", "ignore", "exclude"}
_LIMIT_FIELDS = {f.name for f in fields(Limits)}


def _coerce(key: str, value: Any) -> Any:
    if key in _SEVERITY_KEYS:
        if not isinstance(value, str):
            raise ConfigError(f"{key} must be a severity name, got {type(value).__name__}")
        try:
            return Severity.parse(value)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    if key in _TUPLE_KEYS:
        if isinstance(value, str):
            return (value,)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{key} must be a list of strings")
        return tuple(value)
    if key in _PATH_KEYS:
        return Path(str(value))
    return value


def from_mapping(data: dict[str, Any], source: Path | None = None) -> Config:
    """Build a :class:`Config` from a parsed mapping, rejecting unknown keys."""
    known = {f.name for f in fields(Config)} - {"limits", "source"}
    kwargs: dict[str, Any] = {}
    limit_kwargs: dict[str, Any] = {}

    for key, value in data.items():
        normalised = key.replace("-", "_")
        if normalised == "limits":
            if not isinstance(value, dict):
                raise ConfigError("[limits] must be a table")
            for limit_key, limit_value in value.items():
                limit_name = limit_key.replace("-", "_")
                if limit_name not in _LIMIT_FIELDS:
                    valid = ", ".join(sorted(_LIMIT_FIELDS))
                    raise ConfigError(f"unknown limit {limit_key!r}; valid limits: {valid}")
                limit_kwargs[limit_name] = limit_value
            continue
        if normalised not in known:
            valid = ", ".join(sorted(known))
            raise ConfigError(f"unknown configuration key {key!r}; valid keys: {valid}")
        kwargs[normalised] = _coerce(normalised, value)

    config = Config(**kwargs, source=source)
    if limit_kwargs:
        config.limits = Limits(**{**_limits_as_dict(config.limits), **limit_kwargs})
    return config


def _limits_as_dict(limits: Limits) -> dict[str, Any]:
    return {f.name: getattr(limits, f.name) for f in fields(Limits)}


def load_file(path: Path) -> Config:
    """Load a config file. Supports both a standalone file and pyproject.toml."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc

    if path.name == PYPROJECT:
        section = parsed.get("tool", {}).get("skillsniff")
        if not isinstance(section, dict):
            return Config(source=None)
        return from_mapping(section, path)

    section = parsed.get("skillsniff", parsed)
    if not isinstance(section, dict):
        raise ConfigError(f"{path}: expected a [skillsniff] table")
    return from_mapping(section, path)


def discover(start: Path) -> Config:
    """Walk up from ``start`` looking for a config file; return defaults if none."""
    current = start if start.is_dir() else start.parent
    current = current.resolve(strict=False)

    for directory in (current, *current.parents):
        for name in CONFIG_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return load_file(candidate)
        pyproject = directory / PYPROJECT
        if pyproject.is_file():
            config = load_file(pyproject)
            if config.source is not None:
                return config
    return Config()
