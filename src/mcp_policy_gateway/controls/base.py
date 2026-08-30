"""What every control is, and the context it gets to see.

A control is deliberately small: it is handed one event and returns findings. It holds
no state that survives a call unless it declares it (the budget control does, and says
so), it cannot see other controls' findings, and it cannot stop the chain. Those
restrictions are not ceremony - they are what make the per-control effectiveness table
in the evaluation mean anything. If control B could only ever fire on calls that
control A had already let through, "how much does B catch" would depend on A.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..types import Finding, Stage, ToolCall, ToolDeclaration, ToolResult


@dataclass(slots=True)
class Context:
    """Everything a control may know beyond the event itself.

    Kept explicit rather than reaching for globals so a test can construct exactly the
    world it wants to test, and so the gateway cannot accidentally leak process state
    into a decision.
    """

    #: Absolute path a filesystem tool is confined to, if any.
    sandbox_root: str | None = None
    #: Tool names already claimed, by server, used to detect shadowing.
    claimed_tools: dict[str, str] = field(default_factory=dict)
    #: Host names the deployment considers acceptable egress targets.
    allowed_hosts: frozenset[str] = frozenset()
    #: Tools the operator has explicitly permitted. Empty means "deny everything",
    #: which is the correct default for an allowlist and a common way to get it wrong.
    allowed_tools: frozenset[str] = frozenset()
    #: Tools whose effects cannot be undone and need a human.
    destructive_tools: frozenset[str] = frozenset()
    #: Set by the operator when a human has approved this specific call.
    approved: bool = False


@dataclass(frozen=True, slots=True)
class Event:
    """One thing that happened, at one stage. Exactly one field is populated."""

    stage: Stage
    declaration: ToolDeclaration | None = None
    call: ToolCall | None = None
    result: ToolResult | None = None
    #: The call a result belongs to, so response-stage controls know what was asked.
    origin: ToolCall | None = None

    @property
    def text(self) -> str:
        """The untrusted text this event carries, for controls that scan prose."""
        if self.declaration is not None:
            return self.declaration.description
        if self.result is not None:
            return self.result.text
        return ""


@runtime_checkable
class Control(Protocol):
    """The whole interface. Name is stable: it is a key in the results table."""

    name: str
    stages: frozenset[Stage]

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]: ...
