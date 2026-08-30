"""Limits that hold when nothing is detectably wrong.

Every other control answers "is this call bad?". These answer "has there been too much
of this?", which is a different question and the one that covers attacks nobody wrote a
pattern for. An agent stuck in a retry loop, a tool returning a hundred megabytes of
context, a compromised server drip-feeding calls: none of those trip a content rule, and
all of them are stopped by counting.

This is the only stateful component in the policy layer, which is worth calling out.
Controls elsewhere are pure functions of their event, which is what makes their
individual effectiveness measurable. These are not: their verdict depends on everything
before them in the session. So the state is explicit, owned by the control, and reset
between benchmark cases, and the evaluation notes that its numbers are order-dependent
where the others' are not.

The circuit breaker is separate from the rate limit on purpose. A rate limit says "not
this fast". A breaker says "this tool has failed enough times that the next call is
probably also going to fail, so stop asking" - a statement about the downstream server's
health rather than about the client's behaviour. Conflating them produces a limiter that
punishes a healthy tool for a burst and keeps hammering a broken one.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ..types import Action, Finding, Severity, Stage
from .base import Context, Event


@dataclass(slots=True)
class BudgetLimits:
    """Everything the operator gets to choose. Defaults are deliberately generous."""

    max_calls: int = 50
    max_calls_per_tool: int = 20
    #: Bytes of tool output allowed into context across the session.
    max_result_bytes: int = 2_000_000
    #: Bytes allowed from any single call.
    max_single_result_bytes: int = 256_000
    #: Consecutive failures of one tool before the breaker opens.
    failure_threshold: int = 3


@dataclass(slots=True)
class BudgetControl:
    """Counts calls, bytes and consecutive failures, and refuses past the limits."""

    limits: BudgetLimits = field(default_factory=BudgetLimits)
    name: str = "budget"
    stages: frozenset[Stage] = frozenset({Stage.REQUEST, Stage.RESPONSE})

    calls: int = 0
    calls_by_tool: dict[str, int] = field(default_factory=dict)
    result_bytes: int = 0
    consecutive_failures: dict[str, int] = field(default_factory=dict)
    open_breakers: set[str] = field(default_factory=set)

    def reset(self) -> None:
        self.calls = 0
        self.calls_by_tool.clear()
        self.result_bytes = 0
        self.consecutive_failures.clear()
        self.open_breakers.clear()

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        if event.stage is Stage.REQUEST:
            yield from self._on_request(event)
        else:
            yield from self._on_response(event)

    def _on_request(self, event: Event) -> Iterable[Finding]:
        call = event.call
        if call is None:
            return

        if call.tool in self.open_breakers:
            yield Finding(
                control=self.name,
                rule="circuit_open",
                action=Action.BLOCK,
                severity=Severity.MEDIUM,
                detail=(
                    f"Circuit for {call.tool!r} is open after "
                    f"{self.limits.failure_threshold} consecutive failures."
                ),
            )
            return

        # Counted before the limit test so the call that crosses the line is itself
        # refused, rather than the one after it.
        self.calls += 1
        self.calls_by_tool[call.tool] = self.calls_by_tool.get(call.tool, 0) + 1

        if self.calls > self.limits.max_calls:
            yield Finding(
                control=self.name,
                rule="session_call_budget",
                action=Action.BLOCK,
                severity=Severity.MEDIUM,
                detail=f"Session call budget of {self.limits.max_calls} exhausted.",
            )
        if self.calls_by_tool[call.tool] > self.limits.max_calls_per_tool:
            yield Finding(
                control=self.name,
                rule="per_tool_call_budget",
                action=Action.BLOCK,
                severity=Severity.MEDIUM,
                detail=(
                    f"Tool {call.tool!r} exceeded its budget of "
                    f"{self.limits.max_calls_per_tool} calls."
                ),
            )

    def _on_response(self, event: Event) -> Iterable[Finding]:
        result = event.result
        if result is None:
            return
        tool = event.origin.tool if event.origin else "<unknown>"

        if result.is_error:
            failures = self.consecutive_failures.get(tool, 0) + 1
            self.consecutive_failures[tool] = failures
            if failures >= self.limits.failure_threshold:
                self.open_breakers.add(tool)
                yield Finding(
                    control=self.name,
                    rule="circuit_opened",
                    action=Action.BLOCK,
                    severity=Severity.MEDIUM,
                    detail=f"Opened circuit for {tool!r} after {failures} consecutive failures.",
                )
        else:
            self.consecutive_failures[tool] = 0

        size = len(result.text.encode("utf-8", errors="ignore"))
        self.result_bytes += size

        if size > self.limits.max_single_result_bytes:
            yield Finding(
                control=self.name,
                rule="oversized_result",
                action=Action.BLOCK,
                severity=Severity.MEDIUM,
                detail=(
                    f"Result of {size} bytes exceeds the per-call limit of "
                    f"{self.limits.max_single_result_bytes}."
                ),
            )
        if self.result_bytes > self.limits.max_result_bytes:
            yield Finding(
                control=self.name,
                rule="session_byte_budget",
                action=Action.BLOCK,
                severity=Severity.MEDIUM,
                detail=f"Session output budget of {self.limits.max_result_bytes} bytes exhausted.",
            )
