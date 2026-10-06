"""Scoring the engine on an external corpus, with the internal machinery untouched.

Everything here delegates: `build_context`, `build_event` and `handled` come from
`evaluation/benchmark.py`, and so does `wilson`. That is deliberate and it is the property
worth protecting. If this module grew its own notion of what counts as handled, the external
and internal numbers would stop being comparable, and comparing them is the entire point.

What this module adds is grouping, because the external corpus carries labels the internal
one does not: an eleven-way risk category and a three-way generator. The second grouping is
the one that matters for reading the result. All 485 cases were produced by three templates,
so they are not 485 independent observations; a Wilson interval on the pooled figure will
look tighter than the evidence is. Per-template recall is reported next to it, and when the
templates disagree the pooled number is the less meaningful one.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (str(ROOT / "src"), str(ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from evaluation.benchmark import (  # noqa: E402
    Outcome,
    Report,
    build_context,
    build_event,
    handled,
    wilson,
)

from mcp_policy_gateway.engine import PolicyEngine  # noqa: E402
from mcp_policy_gateway.types import Decision  # noqa: E402

from .adapt import ExternalCase  # noqa: E402

#: caught, total
Tally = tuple[int, int]


@dataclass(slots=True)
class ExternalReport:
    configuration: str
    report: Report
    decisions: dict[str, Decision] = field(default_factory=dict)
    by_security_risk: dict[str, Tally] = field(default_factory=dict)
    by_paradigm: dict[str, Tally] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.report.outcomes)

    @property
    def caught(self) -> int:
        return sum(o.ok for o in self.report.outcomes)

    @property
    def recall(self) -> float:
        return self.caught / self.total if self.total else 0.0

    @property
    def interval(self) -> tuple[float, float]:
        """Sampling error only, and within three templates at that."""
        return wilson(self.caught, self.total)

    def controls(self) -> dict[str, int]:
        """How many caught cases each control fired on."""
        table: dict[str, int] = defaultdict(int)
        for outcome in self.report.outcomes:
            if not outcome.ok:
                continue
            for control in {rule.split(":", 1)[0] for rule in outcome.rules}:
                table[control] += 1
        return dict(sorted(table.items(), key=lambda kv: -kv[1]))

    def missed(self) -> list[Outcome]:
        return [o for o in self.report.outcomes if not o.ok]


def score(
    externals: Sequence[ExternalCase],
    sandbox: str,
    *,
    controls: Sequence[object] | None = None,
    configuration: str = "gateway",
) -> ExternalReport:
    """Run the engine over an external corpus and group by its authors' labels."""
    if controls is None:
        from evaluation.benchmark import DEFAULT_SCHEMAS

        from mcp_policy_gateway.engine import default_controls

        controls = default_controls(schemas=DEFAULT_SCHEMAS)

    outcomes: list[Outcome] = []
    decisions: dict[str, Decision] = {}
    risk: dict[str, list[bool]] = defaultdict(list)
    paradigm: dict[str, list[bool]] = defaultdict(list)

    for external in externals:
        case = external.case
        # Rebuilt per case for the same reason the internal benchmark does it: stateful
        # controls must not carry counts across cases.
        engine = PolicyEngine(controls=list(controls))  # type: ignore[arg-type]
        decision = engine.evaluate(build_event(case), build_context(case, sandbox))

        ok = handled(case, decision)
        decisions[case.case_id] = decision
        outcomes.append(
            Outcome(
                case_id=case.case_id,
                label=case.label,
                attack_class=case.attack_class,
                action=decision.action.value,
                expected=case.expected.value,
                ok=ok,
                rules=decision.rules,
            )
        )
        risk[external.security_risk].append(ok)
        paradigm[external.paradigm].append(ok)

    return ExternalReport(
        configuration=configuration,
        report=Report(configuration=configuration, outcomes=outcomes),
        decisions=decisions,
        by_security_risk=_tally(risk),
        by_paradigm=_tally(paradigm),
    )


def _tally(groups: dict[str, list[bool]]) -> dict[str, Tally]:
    return {
        key: (sum(values), len(values))
        for key, values in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    }


__all__ = ["ExternalReport", "score"]
