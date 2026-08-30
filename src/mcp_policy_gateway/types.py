"""The vocabulary the whole gateway is written in.

Three ideas carry most of the design.

**Stage.** A tool call is not one event, it is three, and they have different threat
models. A server *declares* its tools once (discovery); the client *sends* arguments
(request); the server *returns* content that will be read back into a model's context
(response). Static scanners look at declarations only. A poisoned description is caught
there; an instruction smuggled into a returned document is not, because at declaration
time it did not exist yet. Separating the stages is what lets the same engine answer
both questions, and lets the benchmark report which stage each control actually earns
its place at.

**Action.** Not every finding should stop the call. Blocking a legitimate request is a
real cost, so the engine can also strip the offending span and continue, or hold the
call for a human. Ordering them by severity gives the engine a single rule for
combining findings: the strongest action wins, and every finding is still recorded.

**Finding.** A control never mutates anything and never decides on its own. It reports
what it saw, which rule fired, and how bad it thinks that is. The engine decides. This
is what makes controls independently testable and what makes per-control effectiveness
measurable at all - if controls could short-circuit each other, "what does this one
catch" would have no answer.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Stage(StrEnum):
    """When in the life of a tool call a control gets to look."""

    DISCOVERY = "discovery"
    REQUEST = "request"
    RESPONSE = "response"


class Action(StrEnum):
    """What a control believes should happen. Ordered: later is more severe."""

    ALLOW = "allow"
    SANITISE = "sanitise"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"

    @property
    def severity(self) -> int:
        return _ACTION_ORDER[self]


_ACTION_ORDER: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.SANITISE: 1,
    Action.REQUIRE_APPROVAL: 2,
    Action.BLOCK: 3,
}


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class ToolDeclaration:
    """A tool as the downstream server describes itself. Untrusted input."""

    server: str
    name: str
    description: str = ""
    input_schema: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A request to run a tool. Arguments are untrusted."""

    server: str
    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    call_id: str = ""


@dataclass(frozen=True, slots=True)
class ToolResult:
    """What came back. Untrusted: this text is about to enter a model's context."""

    text: str = ""
    is_error: bool = False


@dataclass(frozen=True, slots=True)
class Finding:
    """One control's observation. Never an instruction - the engine decides."""

    control: str
    rule: str
    action: Action
    severity: Severity
    detail: str
    #: Character span in the inspected text, when the finding points at one. Used by
    #: SANITISE to know what to remove, and by the website to highlight evidence.
    span: tuple[int, int] | None = None


@dataclass(slots=True)
class Decision:
    """The engine's answer for one event, and why."""

    action: Action
    findings: list[Finding] = field(default_factory=list)
    #: Present when the action is SANITISE: the text with offending spans removed.
    sanitised_text: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    @property
    def rules(self) -> list[str]:
        return [f"{f.control}:{f.rule}" for f in self.findings]
