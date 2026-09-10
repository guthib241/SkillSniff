"""JSON output.

The schema is stable and versioned. Everything a consumer needs is in the
document — findings carry their own explanation, impact and remediation rather
than a rule id the consumer has to resolve — so a JSON result is useful without
access to the tool that produced it.
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from skillsniff.model.result import ScanResult

SCHEMA_VERSION = "1.0"


def build(result: ScanResult) -> dict[str, Any]:
    payload = result.as_dict()
    payload["schema_version"] = SCHEMA_VERSION
    payload["disclaimer"] = (
        "A clean result means no issues were detected by the enabled checks. "
        "It is not a guarantee that the skill is safe."
    )
    return payload


def render(result: ScanResult, stream: TextIO | None = None, *, indent: int | None = 2) -> None:
    json.dump(build(result), stream or sys.stdout, indent=indent, sort_keys=False)
    print(file=stream or sys.stdout)
