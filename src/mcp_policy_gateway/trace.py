"""A record of what was decided, written so it can be read back.

The trace is the part an operator actually lives with. A gateway that blocks correctly
and explains nothing is a gateway that gets bypassed the first time it is wrong, because
nobody can tell whether it was wrong. So every decision writes one line: what was asked,
what happened, which rules fired, and how long it took.

**JSON Lines, not a database.** One event per line, appended, never rewritten. It
survives a crash mid-session, it can be tailed, `wc -l` counts it, and reading it back
needs no schema migration. The evaluation and the figures in `assets/` are generated from
this format, so the thing an operator debugs with is the same thing the results are
computed from.

**Payloads are summarised, never stored whole.** A trace that copies every document into
a log file has turned an observability feature into a second copy of the data, in a place
with weaker access control than the original. Text is recorded as a length and a hash;
arguments keep their keys and lose their values unless the value is short and scalar.
Anything a control flagged as a credential is redacted before it reaches this module -
but the summarising happens here too, because a trace writer that trusts its callers to
have redacted is one refactor away from leaking.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from .types import Decision, Stage, ToolCall, ToolResult

#: Values longer than this are summarised rather than recorded.
_MAX_INLINE = 80


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def summarise_value(value: Any) -> Any:
    """Keep a value only if it is small, scalar and unlikely to be a payload."""
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, str):
        if len(value) <= _MAX_INLINE:
            return value
        return {"len": len(value), "sha256_16": _digest(value)}
    if isinstance(value, (list, tuple)):
        return {"type": "array", "len": len(value)}
    if isinstance(value, Mapping):
        return {"type": "object", "keys": sorted(str(k) for k in value)[:20]}
    return {"type": type(value).__name__}


@dataclass(slots=True)
class TraceWriter:
    """Appends one JSON object per decision."""

    path: Path
    session: str
    _handle: TextIO | None = None

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a", encoding="utf-8")

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def __enter__(self) -> TraceWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def record(
        self,
        *,
        stage: Stage,
        decision: Decision,
        call: ToolCall | None = None,
        result: ToolResult | None = None,
        tool: str | None = None,
        micros: float = 0.0,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ts": round(time.time(), 3),
            "session": self.session,
            "stage": stage.value,
            "tool": tool or (call.tool if call else None),
            "action": decision.action.value,
            "rules": decision.rules,
            "micros": round(micros, 1),
            "findings": [
                {
                    "control": f.control,
                    "rule": f.rule,
                    "action": f.action.value,
                    "severity": f.severity.value,
                    "detail": f.detail,
                }
                for f in decision.findings
            ],
        }
        if call is not None:
            entry["arguments"] = {k: summarise_value(v) for k, v in call.arguments.items()}
        if result is not None:
            text = decision.sanitised_text if decision.sanitised_text is not None else result.text
            entry["result"] = {
                "bytes": len(text.encode("utf-8", errors="ignore")),
                "sha256_16": _digest(text),
                "is_error": result.is_error,
                "sanitised": decision.sanitised_text is not None,
            }

        assert self._handle is not None
        self._handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._handle.flush()
        return entry


def read_trace(path: Path) -> list[dict[str, Any]]:
    """Read a trace back. Tolerates a truncated final line from a killed process."""
    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def default_trace_path(root: Path | None = None) -> Path:
    base = root or Path(os.environ.get("MCP_GATEWAY_TRACE_DIR", "runs"))
    return base / f"trace-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
