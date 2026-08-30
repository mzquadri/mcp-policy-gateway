"""Runs the controls and turns their findings into one answer.

The engine is small on purpose. It does three things: ask every control that cares about
this stage, combine what they say, and - if the answer is SANITISE - actually remove the
spans they pointed at. It contains no detection logic of its own, so a rule can never be
hidden here where the results table cannot see it.

**Combining.** The strongest action wins. That is the only sensible rule when controls
are independent: if one says allow and another says block, the call is blocked, and no
weighting scheme would make the allow meaningful. Every finding is kept regardless of
which one won, because "what else did we notice" is the difference between a log line
and an investigation.

**Sanitising.** Spans are removed from the end backwards so earlier offsets stay valid,
and each is replaced with a visible marker rather than deleted silently. A model reading
`[redacted: aws_access_key]` can say something sensible about it; a model reading text
that simply lost a sentence cannot, and neither can the person reading the trace later.

**Ordering.** Controls run in the order given and every one runs, even after a BLOCK.
Short-circuiting would be faster and would make the effectiveness table a lie, because
each control's numbers would depend on what ran before it. The cost is a few microseconds
on calls that were already refused.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .controls.base import Context, Control, Event
from .types import Action, Decision, Finding, Stage


def _merge_spans(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    ordered = sorted(spans)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


@dataclass(slots=True)
class PolicyEngine:
    """Applies an ordered set of controls to an event."""

    controls: Sequence[Control] = field(default_factory=tuple)

    def evaluate(self, event: Event, context: Context) -> Decision:
        findings: list[Finding] = []
        for control in self.controls:
            if event.stage not in control.stages:
                continue
            findings.extend(control.inspect(event, context))

        if not findings:
            return Decision(action=Action.ALLOW)

        action = max((f.action for f in findings), key=lambda a: a.severity)
        decision = Decision(action=action, findings=findings)

        if action is Action.SANITISE:
            decision.sanitised_text = self._sanitise(event.text, findings)
        return decision

    @staticmethod
    def _sanitise(text: str, findings: Sequence[Finding]) -> str:
        replacements = [
            (f.span, f.rule) for f in findings if f.action is Action.SANITISE and f.span
        ]
        if not replacements:
            return text
        # Merge first: two controls flagging overlapping spans must not produce nested
        # markers or corrupt offsets.
        labels = {span: rule for span, rule in replacements}
        out = text
        for span in reversed(_merge_spans(labels)):
            rule = labels.get(span, "policy")
            out = out[: span[0]] + f"[redacted: {rule}]" + out[span[1] :]
        return out


def default_controls(*, schemas: dict | None = None) -> list[Control]:
    """The set used by the CLI, the gateway and the benchmark.

    Ordered cheapest-first so a reader can see the intended cost gradient, though the
    engine runs all of them regardless. Constructed as a function rather than a module
    constant because two of these carry state and sharing one instance between a
    benchmark run and a live session would silently couple them.
    """
    from .controls.arguments import PathSandbox, SchemaConformance
    from .controls.budget import BudgetControl
    from .controls.egress import EgressControl, SecretDisclosure
    from .controls.injection import InstructionInjection
    from .controls.surface import DestructiveAction, ToolAllowlist, ToolShadowing

    return [
        ToolAllowlist(),
        ToolShadowing(),
        DestructiveAction(),
        SchemaConformance(schemas),
        PathSandbox(),
        BudgetControl(),
        SecretDisclosure(),
        EgressControl(),
        InstructionInjection(),
    ]


__all__ = ["Context", "Event", "PolicyEngine", "Stage", "default_controls"]
