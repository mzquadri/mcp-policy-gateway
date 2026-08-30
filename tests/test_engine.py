"""How findings become a decision, and the properties that must hold when they do."""

from __future__ import annotations

from collections.abc import Iterable

from mcp_policy_gateway.controls.base import Context, Event
from mcp_policy_gateway.engine import PolicyEngine, default_controls
from mcp_policy_gateway.types import (
    Action,
    Finding,
    Severity,
    Stage,
    ToolCall,
    ToolResult,
)


class Fixed:
    """A control that always reports the same thing, for testing combination."""

    def __init__(self, name: str, action: Action, span: tuple[int, int] | None = None) -> None:
        self.name = name
        self.stages = frozenset(Stage)
        self._action = action
        self._span = span
        self.calls = 0

    def inspect(self, event: Event, context: Context) -> Iterable[Finding]:
        self.calls += 1
        yield Finding(
            control=self.name,
            rule="fixed",
            action=self._action,
            severity=Severity.LOW,
            detail="",
            span=self._span,
        )


def response(text: str) -> Event:
    return Event(stage=Stage.RESPONSE, result=ToolResult(text=text))


def test_no_findings_means_allow():
    engine = PolicyEngine(controls=[])
    assert engine.evaluate(response("hello"), Context()).action is Action.ALLOW


def test_strongest_action_wins():
    engine = PolicyEngine(
        controls=[Fixed("a", Action.ALLOW), Fixed("b", Action.BLOCK), Fixed("c", Action.SANITISE)]
    )
    assert engine.evaluate(response("x"), Context()).action is Action.BLOCK


def test_approval_outranks_sanitise_and_loses_to_block():
    assert Action.REQUIRE_APPROVAL.severity > Action.SANITISE.severity
    assert Action.REQUIRE_APPROVAL.severity < Action.BLOCK.severity


def test_every_control_runs_even_after_a_block():
    """Short-circuiting would make the per-control effectiveness table meaningless."""
    blocker = Fixed("blocker", Action.BLOCK)
    later = Fixed("later", Action.ALLOW)
    PolicyEngine(controls=[blocker, later]).evaluate(response("x"), Context())
    assert blocker.calls == 1 and later.calls == 1


def test_all_findings_are_kept_not_just_the_winner():
    engine = PolicyEngine(controls=[Fixed("a", Action.BLOCK), Fixed("b", Action.SANITISE)])
    decision = engine.evaluate(response("x"), Context())
    assert {f.control for f in decision.findings} == {"a", "b"}


def test_controls_only_run_at_their_declared_stage():
    control = Fixed("a", Action.BLOCK)
    control.stages = frozenset({Stage.REQUEST})
    engine = PolicyEngine(controls=[control])
    assert engine.evaluate(response("x"), Context()).action is Action.ALLOW
    assert control.calls == 0


def test_sanitise_replaces_the_span_with_a_visible_marker():
    engine = PolicyEngine(controls=[Fixed("a", Action.SANITISE, span=(6, 11))])
    decision = engine.evaluate(response("hello world after"), Context())
    assert decision.sanitised_text is not None
    assert "world" not in decision.sanitised_text
    assert "[redacted: fixed]" in decision.sanitised_text
    assert decision.sanitised_text.startswith("hello ")


def test_overlapping_spans_do_not_corrupt_offsets():
    engine = PolicyEngine(
        controls=[
            Fixed("a", Action.SANITISE, span=(0, 8)),
            Fixed("b", Action.SANITISE, span=(4, 12)),
        ]
    )
    decision = engine.evaluate(response("abcdefghijklmnop"), Context())
    assert decision.sanitised_text is not None
    assert decision.sanitised_text.count("[redacted") == 1
    assert decision.sanitised_text.endswith("mnop")


def test_block_does_not_produce_sanitised_text():
    engine = PolicyEngine(controls=[Fixed("a", Action.BLOCK, span=(0, 3))])
    assert engine.evaluate(response("abcdef"), Context()).sanitised_text is None


def test_rules_are_reported_as_control_colon_rule():
    engine = PolicyEngine(controls=[Fixed("a", Action.BLOCK)])
    assert engine.evaluate(response("x"), Context()).rules == ["a:fixed"]


def test_default_controls_are_independent_instances():
    """Two of them carry state; sharing one set between sessions would couple them."""
    first, second = default_controls(), default_controls()
    assert all(a is not b for a, b in zip(first, second, strict=True))


def test_default_controls_cover_all_three_stages():
    stages = set()
    for control in default_controls():
        stages |= control.stages
    assert stages == set(Stage)


def test_engine_is_pure_for_a_stateless_control_set():
    """Same event twice, same answer - the property the benchmark relies on."""
    engine = PolicyEngine(controls=[c for c in default_controls() if c.name != "budget"])
    context = Context(allowed_tools=frozenset({"read_document"}))
    event = Event(stage=Stage.REQUEST, call=ToolCall(server="s", tool="read_document"))
    first = engine.evaluate(event, context)
    second = engine.evaluate(event, context)
    assert first.action is second.action and first.rules == second.rules
