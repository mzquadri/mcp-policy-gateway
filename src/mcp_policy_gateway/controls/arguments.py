"""What the arguments say they are, and where they actually point.

`SchemaConformance` checks arguments against the schema the server itself declared. That
sounds redundant - the client built the call from that schema - but the client is a
language model, and the schema is the only machine-checkable statement of intent
anywhere in the exchange. Type confusion and smuggled extra keys are cheap to catch here
and expensive to catch later. Only the subset of JSON Schema that servers realistically
publish is implemented: type, required, enum, additionalProperties. An unsupported
keyword is skipped rather than guessed at, so this never blocks on a construct it does
not understand - a deliberate bias toward false negatives in a control whose false
positives would break honest calls.

`PathSandbox` is the one genuinely decidable control in the project. A path either
resolves inside the root or it does not, and the answer does not depend on a heuristic.
It normalises and resolves before comparing, because `../` is the obvious attack and the
one everybody handles. The interesting cases are an absolute path that merely shares a
prefix *string* with the root, and a symlink inside the root pointing out of it; both are
handled here and both are in the corpus.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from ..types import Action, Finding, Severity, Stage
from .base import Context, Event

_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
}

_PATH_KEYS = {"path", "file", "filename", "filepath", "dir", "directory", "target"}


def _type_ok(value: Any, declared: str) -> bool:
    expected = _JSON_TYPES.get(declared)
    if expected is None:
        return True
    if declared in {"integer", "number"} and isinstance(value, bool):
        # bool is an int in Python and is almost never what a numeric schema meant.
        return False
    return isinstance(value, expected)


class SchemaConformance:
    """Checks call arguments against the schema the server published."""

    name = "schema_conformance"
    stages = frozenset({Stage.REQUEST})

    def __init__(self, schemas: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        #: Tool name -> input schema, normally captured at discovery.
        self.schemas: dict[str, Mapping[str, Any]] = dict(schemas or {})

    def learn(self, tool: str, schema: Mapping[str, Any]) -> None:
        self.schemas[tool] = schema

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        call = event.call
        if call is None:
            return
        schema = self.schemas.get(call.tool)
        if not schema:
            return

        properties: Mapping[str, Any] = schema.get("properties", {}) or {}
        required = schema.get("required", []) or []

        for key in required:
            if key not in call.arguments:
                yield Finding(
                    control=self.name,
                    rule="missing_required",
                    action=Action.BLOCK,
                    severity=Severity.MEDIUM,
                    detail=f"Required argument {key!r} is absent.",
                )

        if schema.get("additionalProperties") is False:
            for key in call.arguments:
                if key not in properties:
                    yield Finding(
                        control=self.name,
                        rule="undeclared_argument",
                        action=Action.BLOCK,
                        severity=Severity.HIGH,
                        detail=f"Argument {key!r} is not declared by the tool schema.",
                    )

        for key, value in call.arguments.items():
            spec = properties.get(key)
            if not isinstance(spec, Mapping):
                continue
            declared = spec.get("type")
            if isinstance(declared, str) and not _type_ok(value, declared):
                yield Finding(
                    control=self.name,
                    rule="type_mismatch",
                    action=Action.BLOCK,
                    severity=Severity.MEDIUM,
                    detail=(
                        f"Argument {key!r} is {type(value).__name__}, schema declares {declared}."
                    ),
                )
            allowed = spec.get("enum")
            if isinstance(allowed, list) and value not in allowed:
                yield Finding(
                    control=self.name,
                    rule="enum_violation",
                    action=Action.BLOCK,
                    severity=Severity.MEDIUM,
                    detail=f"Argument {key!r} is not one of the declared values.",
                )


def _looks_like_path(key: str, value: Any) -> bool:
    return bool(value) and isinstance(value, str) and key.lower() in _PATH_KEYS


class PathSandbox:
    """Confines filesystem arguments to a root, after normalisation."""

    name = "path_sandbox"
    stages = frozenset({Stage.REQUEST})

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        call = event.call
        root = context.sandbox_root
        if call is None or root is None:
            return

        resolved_root = Path(root).resolve()
        for key, value in call.arguments.items():
            if not _looks_like_path(key, value):
                continue

            # A Windows-style absolute path or a UNC share reaching out of the sandbox
            # does not look absolute to PurePosixPath, so test both grammars.
            if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
                yield Finding(
                    control=self.name,
                    rule="escapes_sandbox",
                    action=Action.BLOCK,
                    severity=Severity.HIGH,
                    detail=f"Argument {key!r} is an absolute path outside the sandbox root.",
                )
                continue

            candidate = resolved_root / value
            if not candidate.resolve().is_relative_to(resolved_root):
                yield Finding(
                    control=self.name,
                    rule="escapes_sandbox",
                    action=Action.BLOCK,
                    severity=Severity.HIGH,
                    detail=f"Argument {key!r} resolves outside the sandbox root.",
                )
                continue

            # A symlink inside the root pointing out of it is the case a purely textual
            # normalisation misses, because the string never leaves the root.
            if candidate.is_symlink() and not candidate.resolve().is_relative_to(resolved_root):
                yield Finding(
                    control=self.name,
                    rule="symlink_escapes_sandbox",
                    action=Action.BLOCK,
                    severity=Severity.HIGH,
                    detail=f"Argument {key!r} is a link pointing outside the sandbox root.",
                )
